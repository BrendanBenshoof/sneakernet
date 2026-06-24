package com.sneakernet.ui.screens

import android.annotation.SuppressLint
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

private const val TAG = "WebViewScreen"

// JS injected after every page load to fix viewport height.
// The WebView may not have its final size when CSS is first computed, so
// vh/% both resolve to 0. Force body height from the live JS viewport.
private val FIX_VIEWPORT_JS = """
(function(){
  function applyHeight() {
    var h = window.innerHeight + 'px';
    document.documentElement.style.height = h;
    document.body.style.height = h;
  }
  applyHeight();
  window.addEventListener('resize', applyHeight);
  if (window.visualViewport) window.visualViewport.addEventListener('resize', applyHeight);
})();
""".trimIndent()

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebViewScreen() {
    var webView by remember { mutableStateOf<WebView?>(null) }
    var canGoBack by remember { mutableStateOf(false) }

    BackHandler(enabled = canGoBack) {
        webView?.goBack()
    }

    Box(modifier = Modifier.fillMaxSize().systemBarsPadding()) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                // Enable remote Chrome DevTools inspection.
                WebView.setWebContentsDebuggingEnabled(true)

                WebView(context).apply {
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    settings.useWideViewPort = true
                    settings.loadWithOverviewMode = true

                    webViewClient = object : WebViewClient() {
                        override fun shouldOverrideUrlLoading(
                            view: WebView,
                            request: WebResourceRequest,
                        ): Boolean = false

                        override fun doUpdateVisitedHistory(
                            view: WebView,
                            url: String?,
                            isReload: Boolean,
                        ) {
                            canGoBack = view.canGoBack()
                        }

                        override fun onPageFinished(view: WebView, url: String) {
                            view.evaluateJavascript(FIX_VIEWPORT_JS, null)
                        }
                    }
                    loadUrl("http://127.0.0.1:8080/")
                }.also { webView = it }
            }
        )
    }
}
