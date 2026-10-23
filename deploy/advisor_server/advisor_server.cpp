/*
 * advisor_server: Llama 3.2 on ExecuTorch, loaded once, with KV-cache prefix reuse.
 *
 * Native C++ twin of advisor/llm_engine.py, for CPUs where the ExecuTorch pip
 * wheel cannot run. On the Raspberry Pi 4 (Cortex-A72, Armv8.0-A) the wheel's
 * custom LLM ops library is compiled with -march=armv8.2-a and crashes with
 * "Illegal instruction". This server is built from source with the same
 * Pi 4 toolchain and flags as llama_main (-march=armv8-a -mtune=cortex-a72).
 *
 * It keeps the token ids that are already in the model's KV cache. For a new
 * prompt it reads only the tokens after the longest common prefix, so the
 * advisor's fixed prefix (system text + worked examples) is read once.
 * Positions after the current one are never attended to, so old tokens there
 * are simply overwritten by the next prompt.
 *
 * Prompts are read in pieces of --prefill_chunk tokens at fixed positions
 * (0, 32, 64, ...), and the cache is reused only up to such a boundary. A
 * forward call's rounding depends on how the prompt was split into calls (the
 * attention kernel's matrix blocking follows the call length), so without this
 * the same prompt could get a different answer after a different history. With
 * it, every position is computed by the same calls whatever was cached, and
 * GEN reports a CRC-32 of the logits behind its answer to prove it.
 *
 * Protocol (stdin/stdout, one request at a time; logs go to stderr):
 *   request : "<CMD> <max_new_tokens> <nbytes>\n" then exactly <nbytes> bytes of UTF-8 text
 *             CMD = GEN | PREFILL | CHECK | RESET | INFO | QUIT
 *   response: one line of JSON, e.g.
 *             {"ok":true,"text":"...","metrics":{"prompt_tokens":..,...}}
 *             {"ok":false,"error":"..."}
 * At start-up it prints one line: {"ok":true,"event":"ready",...}.
 *
 * Build: deploy/advisor_server/build_pi4.sh (adds this file next to llama_main
 * in your ExecuTorch tree and builds it with the same settings).
 */

#include <executorch/examples/models/llama/runner/runner.h>
#include <executorch/extension/llm/runner/util.h>
#include <executorch/extension/llm/sampler/util.h>
#include <executorch/extension/module/module.h>
#include <executorch/extension/tensor/tensor.h>

#if defined(ET_USE_THREADPOOL)
#include <executorch/extension/threadpool/threadpool.h>
#endif

#include <gflags/gflags.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

DEFINE_string(model_path, "llama3_2.pte", "Exported Llama .pte file.");
DEFINE_string(tokenizer_path, "tokenizer.model", "Llama 3 tokenizer.model.");
DEFINE_int32(cpu_threads, 4, "Threads for the XNNPACK threadpool.");
DEFINE_int32(prefill_chunk, 32,
             "Read prompts in pieces of this many tokens at fixed positions, so an answer "
             "depends only on its prompt. 0 = as few calls as possible (history-dependent rounding).");

using executorch::aten::ScalarType;
using executorch::aten::Tensor;
using executorch::extension::from_blob;
using executorch::extension::Module;
using executorch::runtime::EValue;

namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t0) {
  return std::chrono::duration<double>(Clock::now() - t0).count();
}

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);   // UTF-8 bytes pass through unchanged
        }
    }
  }
  return out;
}

std::string num(double v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%.3f", v);
  return buf;
}

// CRC-32 as in zlib.crc32(data, crc), so Python's LlamaEngine reports the same value.
uint32_t crc32_update(uint32_t crc, const unsigned char* p, size_t n) {
  static const std::array<uint32_t, 256> table = [] {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) {
        c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
      }
      t[i] = c;
    }
    return t;
  }();
  crc = ~crc;
  for (size_t i = 0; i < n; ++i) {
    crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
  }
  return ~crc;
}

class Engine {
 public:
  bool init(std::string& err) {
    auto t0 = Clock::now();
#if defined(ET_USE_THREADPOOL)
    if (FLAGS_cpu_threads > 0) {
      ::executorch::extension::threadpool::get_threadpool()
          ->_unsafe_reset_threadpool(FLAGS_cpu_threads);
    }
#endif
    tokenizer_ = example::load_llama_tokenizer(FLAGS_tokenizer_path);
    if (!tokenizer_) {
      err = "could not load tokenizer " + FLAGS_tokenizer_path;
      return false;
    }
    module_ = std::make_unique<Module>(
        FLAGS_model_path, Module::LoadMode::MmapUseMlockIgnoreErrors);
    if (module_->load_method("forward") != executorch::runtime::Error::Ok) {
      err = "could not load the forward method of " + FLAGS_model_path;
      return false;
    }

    max_seq_len_ = read_int("get_max_seq_len", 128);
    max_context_len_ = read_int("get_max_context_len", max_seq_len_);
    for (int64_t id : read_ints("get_eos_ids")) {
      eos_.insert(static_cast<uint64_t>(id));
    }
    eos_.insert(tokenizer_->eos_tok());

    // One forward call takes at most the exported token-dimension bound
    // (export uses max_seq_len - 1), not max_seq_len itself.
    tokens_per_call_ = 1;
    auto meta = module_->method_meta("forward");
    if (meta.ok()) {
      auto info = meta->input_tensor_meta(0);
      if (info.ok() && info->sizes().size() >= 2) {
        tokens_per_call_ = std::max<int64_t>(1, info->sizes()[1]);
      }
    }
    chunk_ = FLAGS_prefill_chunk > 0 ? std::min<int64_t>(FLAGS_prefill_chunk, tokens_per_call_) : 0;
    load_s_ = seconds_since(t0);
    return true;
  }

  std::string info_json() const {
    std::ostringstream o;
    o << "\"load_s\":" << num(load_s_) << ",\"threads\":" << FLAGS_cpu_threads
      << ",\"max_seq_len\":" << max_seq_len_
      << ",\"max_context_len\":" << max_context_len_
      << ",\"max_tokens_per_call\":" << tokens_per_call_
      << ",\"prefill_chunk\":" << chunk_
      << ",\"kv_tokens\":" << kv_.size() << ",\"exact_tokens\":" << exact_;
    return o.str();
  }

  // Encodes the prompt; chat-template tokens in it are parsed as special tokens.
  bool encode(const std::string& prompt, std::vector<uint64_t>& ids, std::string& err) {
    auto enc = tokenizer_->encode(prompt, /*bos=*/0, /*eos=*/0);
    if (!enc.ok()) {
      err = "tokenizer could not encode the prompt";
      return false;
    }
    ids = enc.get();
    if (ids.empty()) {
      err = "empty prompt";
      return false;
    }
    return true;
  }

  void reset() {   // forget the cache: the next prompt is read in full
    kv_.clear();
    exact_ = 0;
  }

  // True if a PREFILL of these tokens would read nothing new.
  bool is_resident(const std::vector<uint64_t>& ids) const {
    const int64_t n = static_cast<int64_t>(ids.size());
    const int64_t lcp = common_prefix(ids);
    return chunk_ > 0 ? std::min(lcp, exact_) >= n / chunk_ * chunk_ : lcp >= n;
  }

  // Greedy generation with prefix reuse; prefill_only reads the prompt without
  // generating. Returns false and sets err on failure. Same plan as
  // advisor/llm_engine.py:grid_plan.
  bool generate(const std::string& prompt, int64_t max_new, bool prefill_only, std::string& text,
                std::string& metrics, std::string& err) {
    auto t0 = Clock::now();
    std::vector<uint64_t> ids;
    if (!encode(prompt, ids, err)) {
      return false;
    }
    const int64_t n = static_cast<int64_t>(ids.size());
    if (n + max_new > max_context_len_) {
      err = "prompt (" + std::to_string(n) + " tokens) + " + std::to_string(max_new) +
            " new tokens exceeds the model context (" + std::to_string(max_context_len_) + ")";
      return false;
    }
    const int64_t lcp = common_prefix(ids);
    int64_t reuse = 0, end = n;
    if (chunk_ > 0) {
      // Reuse up to a piece boundary that earlier calls computed exactly; a prefill
      // without generation stops at the last full piece (a partial one is never reused).
      reuse = std::min({lcp, prefill_only ? n : n - 1, exact_}) / chunk_ * chunk_;
      end = prefill_only ? n / chunk_ * chunk_ : n;
    } else {
      reuse = std::min<int64_t>(lcp, n - 1);  // at least one token, for fresh logits
    }
    kv_.resize(reuse);
    exact_ = std::min(exact_, reuse);

    // Prefill: read only the tokens after the reused part, piece by piece.
    auto t_prefill = Clock::now();
    const int64_t piece = chunk_ > 0 ? chunk_ : tokens_per_call_;
    int64_t pos = reuse, calls = 0;
    uint64_t next = 0;
    uint32_t crc = 0;
    for (int64_t i = reuse; i < end; i += piece) {
      const int64_t len = std::min(piece, end - i);
      std::vector<int64_t> chunk(ids.begin() + i, ids.begin() + i + len);
      const bool last = i + len >= end;
      if (!step(chunk, pos, next, err, last && !prefill_only ? &crc : nullptr)) {
        return false;
      }
      kv_.insert(kv_.end(), ids.begin() + i, ids.begin() + i + len);
      pos += len;
      ++calls;
    }
    exact_ = chunk_ > 0 ? end / chunk_ * chunk_ : end;
    const double prefill_s = seconds_since(t_prefill);
    const double ttft_s = seconds_since(t0);

    // Decode, greedy, until an end-of-turn token or the limit.
    auto t_decode = Clock::now();
    int64_t generated = 0, decode_calls = 0;
    uint64_t prev = ids.back();
    text.clear();
    while (!prefill_only && eos_.count(next) == 0 && generated < max_new) {
      auto piece = tokenizer_->decode(prev, next);
      if (piece.ok()) {
        text += piece.get();
      }
      prev = next;
      ++generated;
      if (generated == max_new) {
        break;
      }
      std::vector<int64_t> one{static_cast<int64_t>(next)};
      const uint64_t fed = next;
      if (!step(one, pos, next, err, &crc)) {
        return false;
      }
      kv_.push_back(fed);
      ++pos;
      ++decode_calls;
    }
    const double decode_s = seconds_since(t_decode);

    const int64_t prefilled = end - reuse;
    std::ostringstream m;
    m << "{\"prompt_tokens\":" << n << ",\"reused_tokens\":" << reuse
      << ",\"prefill_tokens\":" << prefilled << ",\"prefill_calls\":" << calls
      << ",\"prefill_chunk\":" << chunk_ << ",\"generated_tokens\":" << generated
      << ",\"ttft_s\":" << num(ttft_s) << ",\"prefill_s\":" << num(prefill_s)
      << ",\"decode_s\":" << num(decode_s);
    if (prefilled > 0 && prefill_s > 0) {
      m << ",\"prefill_tok_s\":" << num(prefilled / prefill_s);
    }
    if (decode_calls > 0 && decode_s > 0) {
      m << ",\"decode_tok_s\":" << num(decode_calls / decode_s);
    }
    if (!prefill_only) {
      char hex[16];
      std::snprintf(hex, sizeof(hex), "%08x", crc);
      m << ",\"logits_crc32\":\"" << hex << "\"";
    }
    m << ",\"total_s\":" << num(seconds_since(t0)) << ",\"engine\":\"native\"}";
    metrics = m.str();
    return true;
  }

 private:
  int64_t common_prefix(const std::vector<uint64_t>& ids) const {
    const size_t n = std::min(kv_.size(), ids.size());
    size_t i = 0;
    while (i < n && kv_[i] == ids[i]) {
      ++i;
    }
    return static_cast<int64_t>(i);
  }

  // One forward call; on success `next` is the greedy next token. With crc set,
  // the logits row behind `next` is added to it.
  bool step(std::vector<int64_t>& tokens, int64_t start_pos, uint64_t& next, std::string& err,
            uint32_t* crc = nullptr) {
    auto tokens_tensor = from_blob(
        tokens.data(), {1, static_cast<int>(tokens.size())}, ScalarType::Long);
    std::vector<int64_t> cache_positions;
    int64_t pos = start_pos;
    auto pos_tensor = executorch::extension::llm::populate_start_pos_or_cache_position(
        module_.get(), pos, cache_positions, static_cast<int>(tokens.size()), "forward");
    if (!pos_tensor.ok()) {
      err = "could not build the position input";
      return false;
    }
    std::vector<EValue> inputs{tokens_tensor, *pos_tensor};
    auto out = module_->execute("forward", inputs);
    if (!out.ok() || out->empty() || !(*out)[0].isTensor()) {
      err = "forward failed at position " + std::to_string(start_pos);
      return false;
    }
    const Tensor& logits = (*out)[0].toTensor();
    next = static_cast<uint64_t>(executorch::extension::llm::logits_to_token(logits, 0.0f));
    if (crc != nullptr) {
      const auto* bytes = static_cast<const unsigned char*>(logits.const_data_ptr());
      size_t nbytes = logits.nbytes();
      if (logits.scalar_type() == ScalarType::Float && logits.dim() >= 1) {
        const size_t row = static_cast<size_t>(logits.size(logits.dim() - 1)) * sizeof(float);
        bytes += nbytes - row;                 // the last position's row, as LlamaEngine hashes it
        nbytes = row;
      }
      *crc = crc32_update(*crc, bytes, nbytes);
    }
    return true;
  }

  int64_t read_int(const char* name, int64_t fallback) {
    auto v = read_ints(name);
    return v.empty() ? fallback : v[0];
  }

  std::vector<int64_t> read_ints(const char* name) {
    std::vector<int64_t> values;
    auto names = module_->method_names();
    if (!names.ok() || names->count(name) == 0) {
      return values;
    }
    auto out = module_->execute(name);
    if (!out.ok()) {
      return values;
    }
    for (const auto& v : *out) {
      if (v.isInt()) {
        values.push_back(v.toInt());
      }
    }
    return values;
  }

  std::unique_ptr<::tokenizers::Tokenizer> tokenizer_;
  std::unique_ptr<Module> module_;
  std::vector<uint64_t> kv_;              // token ids in the KV cache, positions 0..size-1
  int64_t exact_ = 0;                     // leading positions computed by full prefill pieces
  std::unordered_set<uint64_t> eos_;
  int64_t max_seq_len_ = 0, max_context_len_ = 0, tokens_per_call_ = 1, chunk_ = 0;
  double load_s_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Keep stdout for the protocol only: anything a library prints goes to stderr.
  int proto_fd = dup(STDOUT_FILENO);
  dup2(STDERR_FILENO, STDOUT_FILENO);
  FILE* proto = fdopen(proto_fd, "w");
  auto reply = [&](const std::string& json) {
    std::fputs(json.c_str(), proto);
    std::fputc('\n', proto);
    std::fflush(proto);
  };

  Engine engine;
  std::string err;
  if (!engine.init(err)) {
    reply("{\"ok\":false,\"event\":\"ready\",\"error\":\"" + json_escape(err) + "\"}");
    return 1;
  }
  reply("{\"ok\":true,\"event\":\"ready\"," + engine.info_json() + "}");

  std::string header;
  while (std::getline(std::cin, header)) {
    std::istringstream h(header);
    std::string cmd;
    long long max_new = 0, nbytes = 0;
    h >> cmd >> max_new >> nbytes;
    if (cmd.empty()) {
      continue;
    }
    if (cmd == "QUIT") {
      reply("{\"ok\":true}");
      break;
    }
    std::string prompt(static_cast<size_t>(std::max(0LL, nbytes)), '\0');
    if (nbytes > 0 && !std::cin.read(&prompt[0], nbytes)) {
      reply("{\"ok\":false,\"error\":\"truncated request\"}");
      break;
    }
    if (cmd == "INFO") {
      reply("{\"ok\":true," + engine.info_json() + "}");
    } else if (cmd == "RESET") {
      engine.reset();
      reply("{\"ok\":true}");
    } else if (cmd == "CHECK") {
      std::vector<uint64_t> ids;
      if (!engine.encode(prompt, ids, err)) {
        reply("{\"ok\":false,\"error\":\"" + json_escape(err) + "\"}");
      } else {
        reply(std::string("{\"ok\":true,\"resident\":") + (engine.is_resident(ids) ? "true" : "false") +
              ",\"prompt_tokens\":" + std::to_string(ids.size()) + "}");
      }
    } else if (cmd == "GEN" || cmd == "PREFILL") {
      std::string text, metrics;
      const bool prefill_only = cmd == "PREFILL";
      const int64_t limit = prefill_only ? 0 : std::max(0LL, max_new);
      if (engine.generate(prompt, limit, prefill_only, text, metrics, err)) {
        reply("{\"ok\":true,\"text\":\"" + json_escape(text) + "\",\"metrics\":" + metrics + "}");
      } else {
        reply("{\"ok\":false,\"error\":\"" + json_escape(err) + "\"}");
      }
    } else {
      reply("{\"ok\":false,\"error\":\"unknown command " + json_escape(cmd) + "\"}");
    }
  }
  return 0;
}
