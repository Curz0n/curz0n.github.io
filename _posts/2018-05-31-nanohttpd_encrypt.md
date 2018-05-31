---
layout: post
title:  利用NanoHTTPD反射调用Android APP加密函数
date:   2018-5-31 14:00:38 +0800
categories: 移动安全
tag: Android Sec
---

* content
{:toc}

{%raw%}  


## 0x00前言  

前段时间刷SRC的时候分析过一个APP，到最后发现被开发坑了一把，接口并没有漏洞。时间投入了不少，最后却没有任何收获，淡淡的忧伤。但是个人觉得分析过程遇到的各种问题以及突破方法还是比较有意思的，所以作为一个案例记录分享一下。  
本文主要涉及的内容包括：  

- 手把手带着逆向分析java层代码  
- 使用NanoHTTPD反射调用加密函数  
- 一些Tips   

## 0x01逆向Java层代码  

### 1.找明文参数  

这一天，发现一个APP登陆支持短信码验证，并且短信码也只有4位数，重放测试发现一直提示"验证码错误"，似乎可以爆破，登录任意用户？  
但是抓个登录包是这个样子的，所以接下来的工作就是破解加密。  

![](/assets/images/2018-05-31-nanohttpd_encrypt/1.png)  

请求的参数被序列化，没有key作为突破口，所以使用接口`loginWithSmsCode`为关键字，定位到关键代码com.xxx.xxx.e.ib类的e方法，e()被a()调用，如下图所示。  

![](/assets/images/2018-05-31-nanohttpd_encrypt/2.png)  

通过打印函数a的调用堆栈，定位到com.lib.http.a.c.a方法，代码详情如下  

![](/assets/images/2018-05-31-nanohttpd_encrypt/3.png)  

经过分析上面a方法的代码逻辑，定位到com.lib.http.b.a抽象类定义的几个抽象方法。抽象类主要定义了请求的接口、响应的处理以及请求数据，详情如下注释：  

![](/assets/images/2018-05-31-nanohttpd_encrypt/4.png)  

光找到抽象定义却没有实际代码逻辑，也没法分析下去。所以接下来需要做的是找到实现。使用`implements 抽象类名`作为关键字，找到com.lib.http.b.a的实现类com.lib.http.b.b，然后定位到请求数据b方法的实现，如下注释  

![](/assets/images/2018-05-31-nanohttpd_encrypt/5.png)  

分析代码可以发现，上图的v2参数很像请求的数据。Hook `i.b`方法，上图的红框部分。得到请求的明文数据，如下图所示  

![](/assets/images/2018-05-31-nanohttpd_encrypt/6.png)  

**Tips：**  

分析代码找到明文参数的这一段过程中，除了读代码硬性要求以外，我们使用了3个小技巧：  

- 没有"明文"参数作为切入点，使用接口作为关键字，找到代码分析入口。  
- 打印调用堆栈，快速定位关键函数。  
- 查找抽象类的具体实现，使用`implements xxx`作为搜索技巧。  

### 2.分析加密函数  

到这里本以为能那么"轻轻松松"的搞定，结果还是我太图样...，从开始burp抓的数据包知道这个数据不是简单的加密，应该是序列化的一个对象，最后发送的是byte流。  
所以接下的工作就是分析这段明文数据是如何被序列化成byte流的，然后把这段逻辑抠出来，使用burp插件实现。  
继续查看i.b方法，b方法的逻辑如下，将数据做了gzip压缩  

![](/assets/images/2018-05-31-nanohttpd_encrypt/7.png)  

上图就只做了gzip压缩，没有其他操作。那返回去继续分析请求b的实现，

![](/assets/images/2018-05-31-nanohttpd_encrypt/8.png)  

看代码逻辑可知gzip加密后的byte[]又传入了com.xx.xxxx.u.b.a().a方法，代码跟过去详情如下  

![](/assets/images/2018-05-31-nanohttpd_encrypt/9.png)  

继续追踪a方法，又是一个抽象类  

![](/assets/images/2018-05-31-nanohttpd_encrypt/10.png)  

然后找到实现类com.xx.xxxxx.u.h  

![](/assets/images/2018-05-31-nanohttpd_encrypt/11.png)  

跟着看c函数  

![](/assets/images/2018-05-31-nanohttpd_encrypt/12.png)  

这里调用了`staticBinarySafeEncryptNoB64`方法，双击该方法，发现也是一个抽象方法。  
然后我们继续找`staticBinarySafeEncryptNoB64`的实现，很操蛋...主dex里面搜索不到实现类，只能找到定义的抽象类，如下  

![](/assets/images/2018-05-31-nanohttpd_encrypt/13.png)  

### 3.突破防御，追寻加密核心逻辑  

分析过程很艰辛，一开始以为是核心代码做了加固处理。最终经过蛋疼的分析，发现\lib\armeabi\libxxxmain.so很有猫腻。如下所示，就是so里面藏了一个dex和so，很有意思。  

![](/assets/images/2018-05-31-nanohttpd_encrypt/14.png)  

打开so里面的dex，果然一下就找到了staticBinarySafeEncryptNoB64的实现  

![](/assets/images/2018-05-31-nanohttpd_encrypt/15.png)  

跟着代码逻辑最终我们需要追踪doCommand方法，直接点击没反应。那就查看调用该方法的getRouter()函数。

![](/assets/images/2018-05-31-nanohttpd_encrypt/16.png)  

getRouter()返回`IRouterComponent`，然后调用`doCommand()`,所以需要找到IRouterComponent类的详情。发现又回到了主dex，当然不出意外的又是一个抽象，很操蛋。  

![](/assets/images/2018-05-31-nanohttpd_encrypt/17.png)  

继续找它的实现类，又回到了\lib\armeabi\lixxxain.so下面的dex  

![](/assets/images/2018-05-31-nanohttpd_encrypt/18.png)  

然后分析到最后，发现核心逻辑在native里面...心中神兽奔涌。  

![](/assets/images/2018-05-31-nanohttpd_encrypt/19.png)  

猜测实现so就是\lib\armeabi\libxxxmain.so下面的\lib\armeabi\libxxxmainso-xxx80.so. 把libxxxmain.so改成压缩包格式，使用zip解压.然后拿到libxxxmainso-xxx80.so  

![](/assets/images/2018-05-31-nanohttpd_encrypt/20.png)  

到这里，login的java层逻辑分析完毕，接着该分析so里面加密的具体逻辑了。但是通过前面的分析发现，这个加密过程不是一般的复杂。所以如果想通过复现加密逻辑的方法的话，应该会遇到很多不可预知的trouble。并且直觉告诉我，这个so也不简单，所以我打算放弃分析so，采用另外一种方法。  

## 0x02使用NanoHTTPD反射调用加密函数  

### 1.使用xposed搭载NanoHTTPD  

什么是NanoHTTPD？NanoHTTPD是一个免费、轻量级的(只有一个Java文件) HTTP服务器，可以很好地嵌入到Java程序中。支持 GET, POST, PUT等请求，支持文件上传，占用内存很小。项目地址：[https://github.com/NanoHttpd/nanohttpd](https://github.com/NanoHttpd/nanohttpd)  

使用这个微型服务器能做什么呢？先说下需求目的以及处理思路:  

1. 首先明确目标是爆破短信码。因为数据包被加密，所以第一步需要拿到明文数据包。这个在第一步已经hook到了！  
2. 拿到明文数据包后开始遍历短信码，然后将每次更新的短信码的数据包发送给服务器，直到短信被爆破。  
3. 篡改短信码后需要把明文数据包还原成加密状态才可以发送给服务器。但是现在复现加密逻辑遇到一些障碍，如果我们可以直接调用APK里面的加密方法，那整个加密过程是不是变得非常easy了呢!  

有了处理思路，那具体怎么实现呢?  
我们可以在手机里面搭建一个NanoHTTPD微型服务器，然后使用脚本发送文明数据给NanoHTTPD，接着反射调用app的加密函数给明文数据加密。然后再把加密过后的密文返回给脚本，最后使用脚本发送请求给服务器。流程图如下：  
![](/assets/images/2018-05-31-nanohttpd_encrypt/20_1.png)

具体从哪个函数开始入手呢，当然还是得从处理请求数据的com.lib.http.b.b的b方法开始.  

![](/assets/images/2018-05-31-nanohttpd_encrypt/21.png)  

通过之前的分析我们知道，明文数据包先是传入i.b进行gzip压缩，然后再传入com.xxx.xxx.u.b.a().a()进行一系列的加密处理。所以我们可以把gzip压缩这段逻辑抽出来单独处理，再反射调用com.xxx.xxx.u.b.a().a()方法对压缩结果进行加密，然后一切的一切都变得简单了。来具体看下com.xxx.xxx.u.b.a().a()的实现如下:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/22.png)  

a(byte[] arg)方法本身没什么焦点可关注，但是它不是static的，所以在调用它之前，我们必须得先有一个对象b。而类b的构造方法又是private，所以不能够直接newInstance。但是他在静态代码块static里面初始化的时候，new了一个对象并赋值给变量c。所以我们可以反射拿到变量c，就相当于拿到了b对象的实例。到此所有逻辑都捋清楚了，下面看具体的实现:

![](/assets/images/2018-05-31-nanohttpd_encrypt/23.png)  

这里对代码简单的说明下，首先在Xposed中搭载NanoHTTPD开启一个HTTP服务，设置端口8899。然后在处理请求数据的server方法中(请求数据就是明文数据包)，先将数据进行gzip压缩，然后反射调用上述分析的加密函数com.xxx.xxx.u.b.a().a(byte[] arg)。因为a(byte[] arg)不是静态方法，所以需要先反射拿到静态代码块里面初始化时new的b对象(变量c)。然后将对象和需要加密的数据传入callMethod调用加密函数a，最后再返回加密后的数据给客户端(脚本)。  
发送给NanoHTTPD服务器的脚本实现如下:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/24.png)  

还是对代码简单解读下，首先我们拿到最开始分析时，hook到的明文数据(代码中params参数)，然后遍历明文数据中的smsCode进行短信码爆破。并把每次更新的数据作为参数向NanoHTTPD服务器请求(encrypt方法)，NanoHTTPD服务器会反射调用APP中的加密函数对明文数据进行加密，最后把加密后的结果返回回来，然后再拿着NanoHTTPD返回的密文向应用服务器发起请求。  
最终爆破短信码的效果如下图:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/25.png)  

### 2.burpsuite拷贝数据流  

最后结果当然是没有爆破成功，如果成功就见不到这篇文章了!!(再次吐槽下，操蛋的开发，把账号锁定和验证码错误的提示搞成一样的，毫无用户体验，被迷惑了...白干一场……&*%￥￥)  
虽然失败了，但是后面还有点细节需要注意，做个笔记吧。  
假如爆破成功了，那我们可以在burp的history看见记录的数据包。效果如下图所示:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/26.png)  

这里可以看见服务器响应的数据也是加密后的byte流。最开始尝试直接粘贴替换response，结果一直不成功。以为还是得去调用APP里面的方法解密数据，然后再hook替换数据啥的...于是又去分析了下APP，发现要调用response的解密函数有点复杂。一番思索后还是觉得直接替换response方便。通过将复制粘贴的数据和元数据的Text对比，发现没有什么异常。然后对比HEX发现原来是回车换行的原因，如下所示:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/27.png)  

既然原因找到了就好办，那我们不用Ctrl+C和Ctrl+V的方式，直接保存数据元，如下图所示:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/28.png)  

然后替换response的时候再paste file即可，如下:  

![](/assets/images/2018-05-31-nanohttpd_encrypt/29.png)  

## 0x03 结语  

虽然漏洞没挖到，但是在分析过程中踩的各种坑还是蛮有意义的，比如将核心代码编译成dex藏在so里面，调用各种抽象方法各种绕最后把加密逻辑使用native实现等等。以及使用NanoHTTPD反射调用加密函数，利用这种方法，不管app的加密如何复杂，其实都能够cover的。因为分析这个App和写这篇博客的时间间隔比较久了，所以有些细节不能顾及，权当做一次漏洞挖掘的流水账吧！  
**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}
