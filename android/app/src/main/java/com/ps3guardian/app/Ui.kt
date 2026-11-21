package com.ps3guardian.app

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.View
import android.widget.ImageView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/** Colours, words and small helpers shared by the screens (app 3.0, charcoal and ivory). */
object Ui {
    const val VERSION = "3.1"

    /** How a verdict looks: its word, its colour, the dark tint behind it, the ink on it, a soft text colour. */
    class Look(val word: String, val color: Int, val tint: Int, val ink: Int, val soft: Int, val icon: Int)

    fun look(c: Context, verdict: String): Look = when (verdict) {
        "dangerous" -> Look("Dangerous", c.getColor(R.color.danger), c.getColor(R.color.danger_tint),
            c.getColor(R.color.danger_ink), c.getColor(R.color.danger_soft), R.drawable.ic_danger)
        "suspicious" -> Look("Suspicious", c.getColor(R.color.warn), c.getColor(R.color.warn_tint),
            c.getColor(R.color.warn_ink), c.getColor(R.color.warn_soft), R.drawable.ic_warn)
        "safe" -> Look("Safe", c.getColor(R.color.safe), c.getColor(R.color.safe_tint),
            c.getColor(R.color.safe_ink), c.getColor(R.color.safe_soft), R.drawable.ic_safe)
        "unknown" -> Look("Not checked", c.getColor(R.color.text_2), c.getColor(R.color.raised),
            c.getColor(R.color.ivory), c.getColor(R.color.text_2), R.drawable.ic_info)
        else -> Look("Checking", c.getColor(R.color.text_2), c.getColor(R.color.raised),
            c.getColor(R.color.ivory), c.getColor(R.color.text_2), R.drawable.ic_clock)
    }

    fun dp(c: Context, v: Int): Int = (v * c.resources.displayMetrics.density + 0.5f).toInt()

    fun rounded(color: Int, radiusPx: Float): GradientDrawable {
        val d = GradientDrawable()
        d.setColor(color)
        d.cornerRadius = radiusPx
        return d
    }

    fun circle(color: Int): GradientDrawable {
        val d = GradientDrawable()
        d.shape = GradientDrawable.OVAL
        d.setColor(color)
        return d
    }

    fun tint(icon: ImageView, color: Int) {
        icon.imageTintList = ColorStateList.valueOf(color)
    }

    /** A verdict's icon in its circle: the colour itself (strong) or its dark tint. */
    fun verdictIcon(box: View, icon: ImageView, look: Look, strong: Boolean) {
        box.background = circle(if (strong) look.color else look.tint)
        icon.setImageResource(look.icon)
        tint(icon, if (strong) look.ink else look.color)
    }

    /** "Dangerous · SMS" with the word in its colour. */
    fun verdictLine(word: String, color: Int, rest: String): CharSequence {
        val s = SpannableString(if (rest.isBlank()) word else "$word · $rest")
        s.setSpan(ForegroundColorSpan(color), 0, word.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        return s
    }

    fun channelLabel(channel: String, app: String?): String = when (channel) {
        "chat" -> if (app != null) ChatApps.label(app) else "Chat"
        "share" -> "Checked by you"
        "file" -> "Shared file"
        "test" -> "Test"
        else -> "SMS"
    }

    private fun day(ms: Long): Int {
        val cal = Calendar.getInstance()
        cal.timeInMillis = ms
        return cal.get(Calendar.YEAR) * 1000 + cal.get(Calendar.DAY_OF_YEAR)
    }

    private fun daysAgo(ms: Long, now: Long): Int {
        val cal = Calendar.getInstance()
        cal.timeInMillis = now
        for (n in 0..1) {
            if (day(ms) == day(cal.timeInMillis)) return n
            cal.add(Calendar.DAY_OF_YEAR, -1)
        }
        return 2
    }

    fun clock(ms: Long): String = SimpleDateFormat("H:mm", Locale.US).format(Date(ms))

    /** "TODAY", "YESTERDAY" or "MON, 17 NOV": the Alerts page's day headings. */
    fun dayName(ms: Long, now: Long): String = when (daysAgo(ms, now)) {
        0 -> "TODAY"
        1 -> "YESTERDAY"
        else -> SimpleDateFormat("EEE, d MMM", Locale.US).format(Date(ms)).uppercase(Locale.US)
    }

    /** "9:41" today, "17 Nov" before: the time at the end of a list row. */
    fun shortTime(ms: Long, now: Long): String =
        if (daysAgo(ms, now) == 0) clock(ms) else SimpleDateFormat("d MMM", Locale.US).format(Date(ms))

    /** "Today, 9:41", "Yesterday, 18:20" or "17 Nov, 18:20". */
    fun whenText(ms: Long, now: Long): String = when (daysAgo(ms, now)) {
        0 -> "Today, ${clock(ms)}"
        1 -> "Yesterday, ${clock(ms)}"
        else -> SimpleDateFormat("d MMM", Locale.US).format(Date(ms)) + ", " + clock(ms)
    }

    // A link or a website's name: scheme (optional), host with at least one dot, then the rest.
    private val URLISH = Regex("(?i)\\b(https?://)?((?:[a-z0-9-]+\\.)+[a-z]{2,})(\\S*)")

    /** "http://sbi-kyc.example/update" -> "hxxp://sbi-kyc[.]example/update": shown, never opened. */
    fun defang(text: String): String = URLISH.replace(text) { m ->
        m.groupValues[1].replace(Regex("(?i)^http"), "hxxp") + m.groupValues[2].replace(".", "[.]") + m.groupValues[3]
    }

    /**
     * Draws the screen behind the status and navigation bars (Android 15 does so anyway): the
     * top spacer takes the status bar's height, the bottom view (the tab bar or the buttons) gets
     * the navigation bar's height, or the keyboard's, under its own padding.
     */
    fun edgeToEdge(a: Activity, root: View, top: View, bottom: View?) {
        WindowCompat.setDecorFitsSystemWindows(a.window, false)
        val basePad = bottom?.paddingBottom ?: 0
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val params = top.layoutParams
            params.height = bars.top
            top.layoutParams = params
            val under = maxOf(bars.bottom, ime.bottom)
            if (bottom != null) {
                bottom.setPadding(bottom.paddingLeft, bottom.paddingTop, bottom.paddingRight, basePad + under)
                root.setPadding(bars.left, 0, bars.right, 0)
            } else {
                root.setPadding(bars.left, 0, bars.right, under)
            }
            insets
        }
    }
}
