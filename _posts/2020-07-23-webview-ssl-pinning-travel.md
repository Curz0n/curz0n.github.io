---
layout: post
title: 一次WebView证书校验的踩坑记录  
date: 2020-07-22 21:11:05 +0800
categories: 移动安全
tag: WebView  
---

* content
{:toc}

{%raw%}  

## 0x00 背景  

WebView发起https请求时使用系统预装CA证书校验，把burp证书导入到系统证书库里面，期望是可以直接抓取到请求报文，但结果却是死活抓不到数据包。使用相同证书校验方式的OKhttp发起的https请求却可以正常抓包。   

## 0x01 踩坑过程  

### 1. 测试信息  

- 手机系统：Android 8.1  
- Webview请求bing.com站点，开启代理后请求异常  
- OKhttp请求baidu.com站点，开启代理后请求正常  

### 2. 分析过程  

WebView示列代码如下  

```java
......SNIP......
        mWebview.setWebViewClient(new WebViewClient(){
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                    //super.onReceivedSslError(view, handler, error);
                    handler.cancel();
            }
        });
......SNIP......
        mWebview.loadUrl("https://cn.bing.com/?q=webview_defaultCerts");
......SNIP......
```

运行程序，请求目标报错如下  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/2.png)  

错误代码3，表示"证书发布机构不信任"  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/3.png)  

通过资料查询，Android 5.0开始，WebView移植成了一个独立的apk，具体可以在`设置-开发者选项->WebView实现`看到WebView的当前版本。并且某些版本对有些证书机构拉了黑名单，所以开始怀疑是Webview版本问题，通过对Webview升级，发现问题依旧存在。  

### 3. 突破点  

通过运行日志分析，发现第一次请求目标都有如下报错  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/4.png)  

可以看见这是Log.i打印的日志，Hook一下`android.util.Log`并打印调用栈  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/5.png)  

是`org.chromium.net.X509Util.verifyServerCertificates`调用并打印的日志，看包名预测是Webview这个App，把Webview APP导出到本地`adb pull /system/app/WebViewGoogle/WebViewGoogle.apk .`，定位到关键代码处  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/6.png)  

分析代码，最后在Webview App中定位到如下位置  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/7.png)  

通过X509TrustManagerExtensions类的包名，可知方法实现应该在Android源码中  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/8.png)  

这里进入第100行的mDelegate.checkServerTrusted方法，mDelegate变量是TrustManagerImpl对象，该对象在com.android.org.conscrypt包下，如下所示  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/9.png)  

源码中搜索，死活搜不到该包名下的实现，只能在org.conscrypt包下找到  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/10.png)  

那就分析org.conscrypt包下的代码，定位到`checkTrusted`方法  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/10_1.png)  

测试发现，okhttp请求baidu和webview请求bing，在调用到checkTrusted方法时，传入方法的参数都是一样的，奇怪的地方是执行到495行调用checkTrustedRecursive方法，倒数第二个变量trustedChain突然不同，okhttp传入了burp证书，webview传入为null，通过分析checkTrusted方法的内部逻辑，发现并没有逻辑去判断导致trustedChain变量不同。陷入僵局，一度怀疑是包名不同，所以这里的源码和手机系统里面的源码有区别。  

进入手机系统，在`/system/framework`找下对应的源码，关键字匹配一下，定位到如下vdex  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/11.png)  

把vdex拉出来，使用[vdexExtractor](https://github.com/anestisb/vdexExtractor)转换成dex  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/12.png)  

然后找到对应的代码，包名是对得上了，但是代码逻辑和org.conscrypt包下逻辑并没有什么不同  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/13.png)  

hook checkTrustedRecursive方法，打印调用栈，仔细分析打印的堆栈信息，发现checkTrustedRecursive方法被调用了多次，第一次调用的时候，OKhttp和Webview传入的参数是一样的，第二次调用时，倒数第二个变量trustedChain才有了变化（okhttp传入burp证书，webview传入null）。checkTrustedRecursive方法详情如下（代码有点长）  

![](/assets/images/2020-07-23-webview-ssl-pinning-travel/15.png)  

通过调用栈分析，OKhttp请求的baidu在第560行调用了自己，Webview请求的bing是在第605行调用自己，这里非常奇怪，因为第一次进入checkTrustedRecursive方法传入的参数是一模一样的，在550行-558行似乎也没有逻辑去判断，导致webview会跳过550行的foreach。最后分析548行的findAllTrustAnchorsByIssuerAndSignature方法，打印返回的Set集合的size，发现OKhttp请求baidu的size=1，Webview访问bing的size=0，因为size=0，所以foreach就会直接跳过，直接跳到573行去。然后分析findAllTrustAnchorsByIssuerAndSignature里面的逻辑，突然灵感一来，怀疑是bing站点在network_security_config.xml配置文件中固定了证书，所以导致将burp证书导入系统证书库也抓包失败，查看工程代码，确实是自己2222222了...吐血...  

## 0x02 结语  

问题的起因很狗血，分析过程也很坎坷，记录一个流水账。  

**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}  