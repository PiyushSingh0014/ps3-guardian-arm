package com.ps3guardian.app

import android.view.View
import android.widget.LinearLayout
import android.widget.TextView

/** Alerts: every checked message, newest first, by day, with All, Scams and Safe. */
class AlertsPage(private val a: MainActivity, private val root: View) {
    private var filter = "all"
    private val list: LinearLayout = root.findViewById(R.id.alerts_list)
    private val empty: TextView = root.findViewById(R.id.alerts_empty)
    private val chips = listOf("all" to R.id.chip_all, "scams" to R.id.chip_scams, "safe" to R.id.chip_safe)

    init {
        for ((f, id) in chips) {
            root.findViewById<View>(id).setOnClickListener {
                filter = f
                refresh()
            }
        }
    }

    fun refresh() {
        for ((f, id) in chips) {
            val chip = root.findViewById<TextView>(id)
            val on = f == filter
            chip.setBackgroundResource(if (on) R.drawable.bg_chip_on else R.drawable.bg_chip_off)
            chip.setTextColor(a.getColor(if (on) R.color.ink else R.color.text_2))
        }
        val now = System.currentTimeMillis()
        val shown = History.entries(a).filter {
            when (filter) {
                "scams" -> it.flagged
                "safe" -> it.verdict == "safe"
                else -> true
            }
        }
        list.removeAllViews()
        for ((day, items) in shown.groupBy { Ui.dayName(it.time, now) }) {      // newest day first
            val group = a.layoutInflater.inflate(R.layout.group_day, list, false)
            group.findViewById<TextView>(R.id.group_name).text = day
            val rows = group.findViewById<LinearLayout>(R.id.group_rows)
            items.forEachIndexed { i, e -> rows.addView(Rows.entry(a, rows, e, last = i == items.size - 1, note = true)) }
            list.addView(group)
        }
        empty.text = when (filter) {
            "scams" -> "No scams found. Messages Sajag flags appear here."
            "safe" -> "No safe messages yet."
            else -> "Nothing checked yet. Every message Sajag checks appears here, newest first."
        }
        empty.visibility = if (shown.isEmpty()) View.VISIBLE else View.GONE
    }
}
