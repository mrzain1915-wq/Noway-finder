package com.noway.finder

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import com.chaquo.python.Python
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {
    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    return false
                }
            }
            setDownloadListener { url, _, _, _, _ ->
                // Export downloads (CSV/TXT/ZIP) open in the browser, which saves the file.
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            }
        }
        setContentView(webView)
        webView.loadData(LOADING_HTML, "text/html", "UTF-8")
        startServer()
        waitForServer()
    }

    private fun startServer() {
        Thread {
            try {
                val db = File(filesDir, "finder.sqlite3").absolutePath
                val cache = cacheDir.absolutePath
                Python.getInstance().getModule("finderapp").callAttr("start", db, cache)
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Finder failed to start: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun waitForServer() {
        Thread {
            var up = false
            for (i in 1..120) {
                try {
                    val conn = URL("http://127.0.0.1:8765/api/status").openConnection() as HttpURLConnection
                    conn.connectTimeout = 1000
                    conn.readTimeout = 1000
                    if (conn.responseCode == 200) {
                        up = true
                        conn.disconnect()
                        break
                    }
                    conn.disconnect()
                } catch (_: Exception) {
                }
                Thread.sleep(500)
            }
            runOnUiThread {
                if (up) webView.loadUrl("http://127.0.0.1:8765/")
                else webView.loadData(ERROR_HTML, "text/html", "UTF-8")
            }
        }.start()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (::webView.isInitialized && webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    companion object {
        private const val LOADING_HTML =
            "<html><body style='font-family:sans-serif;padding:40px'><h2>NOWAY Finder is starting…</h2><p>The local discovery engine is starting. This takes a few seconds the first time.</p></body></html>"
        private const val ERROR_HTML =
            "<html><body style='font-family:sans-serif;padding:40px'><h2>Finder did not start</h2><p>Close the app and open it again. If it keeps failing, restart your phone and try once more.</p></body></html>"
    }
}
