---
layout: post
title: 浅谈前端JS加密报文的几种破解方法
# date: 2019-12-22 13:00:05 +0800
date : 2019-12-24 23:30:00 +0800
categories: Web安全
tag: JS加解密
---

* content
{:toc}

{%raw%}  

## 0x00 前言  

移动安全领域，为了防止APP应用数据包被中间人分析篡改，通常会在APP内使用加密算法对传输的数据报文进行二次加密或签名，攻击者即使在HTTPS协议保护的传输层之前获取到数据报文，也不能直接对报文进行分析篡改，对于这类防御策略，攻击方通常会采用hook技术进行对抗。在Web应用领域，安全意识较强的厂商会利用JavaScript脚本对数据报文进行二次加密，以达到和移动APP对数据报文一样的保护效果，但是由于前端JavaScript脚本开源的特殊性质，可以非常容易的获取到源码，并且利用浏览器自带的开发者工具对代码进行调试分析，为了防止加密算法泄漏，通常会选择牺牲一定的性能来换取更高的攻击门槛，比如对JavaScript脚本代码进行混淆加密、插入反调试检测代码等。笔者孤陋寡闻，并不清楚是否存在现成的hook框架对抗前端JS加密，但是基于JS运行环境的特殊性，我们可以一起来探讨下对于混淆加密后的JS加密算法破解的几种可行方法。  

## 0x01 环境准备    

### 1. 了解JavaScript混淆加固  

简单来说，所谓JS混淆加固其实就是在保证JS原始功能不改变的情况下，删除代码中尽可能多的有意义的信息，然后对变量名、常量、代码执行流程进行混淆，注入废逻辑代码、反调试代码，目的在于让人无法直接读懂代码，一个示例：  

源码如下

```javascript
var test = 'hello';
```

对常量进行Base64编码加密混淆  

```javascript
var _0x9d2b = ['aGVsbG8=']; // base64编码后的字符串

var _0xaf421 = function (_0xab132) {
    // base64解码函数
    var _0x75aed = function(_0x2cf82) {
        // TODO: 解码
    };
    return _0x75aed(_0xab132);
}

var _0xb7de = function (_0x4c7513) {
    _0x4c7513 = _0x4c7513 - 0x0;
    var _0x96ade5 = _0xaf421(_0x9d2b[_0x4c7513]);
    return _0x96ade5;
};

var test = _0xb7de('0x0');
```

从示例可以看见，一行简单的常量字符串定义，通过加密混淆以后，代码变的比较晦涩难懂，如果原始代码逻辑和混淆算法都比较复杂，那最后通过混淆之后的代码，对于人类来说，是非常非常不友好的。但是对于计算机来说呢？无论流程变得多么复杂，最终都会还原成原始功能的代码，比如上述的示例，直接在最后一行下个断点，动态调试一下就能获取到test变量的真实值。  

### 2. 靶机搭建  

根据业务场景先写个靶机应用作为研究对象，前端页面如下，使用fetch发送post请求，请求参数调用s函数计算消息摘要防止被中间人篡改，sign.js使用requireJS框架异步加载:    

![](/assets/images/2019-12-25-js-decrypt/1.png)  

sign.js是md5算法实现，源码[戳这里](https://github.com/blueimp/JavaScript-MD5)，适配requireJS框架及加密算法调用的关键代码如下    

![](/assets/images/2019-12-25-js-decrypt/2.png)  

把sign.js核心算法使用某大牛提供的混淆工具加固一下，加固以后的部分效果，没有md5等关键字，无法静态分析出具体算法:  

![](/assets/images/2019-12-25-js-decrypt/3.png)  

运行靶机，抓取到数据包正常响应如下  

![](/assets/images/2019-12-25-js-decrypt/4.png)  

篡改数据报文，服务端因签名校验失败，会使请求失败  

![](/assets/images/2019-12-25-js-decrypt/5.png)  

假如我们不知道sign.js源码实现，通过浏览器获取到的只是混淆加固以后的sign.js，为了能正常对请求参数进行安全性测试，就需要逆出sign字段的算法实现，下面以该靶机作为研究对象，看看可以如何突破经过加密混淆之后的js算法。  

## 0x02 JS加固混淆对抗  

### 1. 动态调试获取加密算法  

#### 1.1 定位关键代码  

想要修改post数据包中的数据，对其进行安全性测试，首要条件就是绕过sign校验，所以需要逆出生成sign字段的算法，在篡改post数据包之后，能够重新计算出消息摘要，然后替换原始的sign值，使服务器校验通过。  
我们通过关键字先定位到比较核心的代码处，方便下断点开始调试分析。使用Chrome浏览器打开开发者工具，切换到Sources界面，Command+Option+F全局搜索，找到关键代码在search.html中  

![](/assets/images/2019-12-25-js-decrypt/6.png)  

分析代码，很明显sign签名值是通过第10行的s函数计算出的，在第10行下个断点开始调试  

![](/assets/images/2019-12-25-js-decrypt/7.png)  

当打开开发者工具后，发现会自动进入到sign.js，利用Chrome自带的格式化工具，对压缩的JS代码进行格式化  

![](/assets/images/2019-12-25-js-decrypt/8.png)  

发现有反调试检测，断点一直停留在sign.js的1232行，无法继续运行代码   

![](/assets/images/2019-12-25-js-decrypt/9.png)  

#### 1.2 反调试绕过  

分析这段代码和调用堆栈，可知在1248行的else语句进入的反调试状态:    

![](/assets/images/2019-12-25-js-decrypt/10.png)  

接着看代码，可知是1238的if结果为false才进入了else，在1238行下个断点，动态修改if结果，把undefined修改成一个非0值就可以进入if语句，绕过反调试检测  

![](/assets/images/2019-12-25-js-decrypt/11.png)  

F8运行到下一个断点，自动停留到了search.html第10行断点处，接着就可以动态的一步一步去调试sign.js中的算法实现了。把Chrome格式化后的代码保存到本地，命名为sign_format.js，简单分析下格式化后的代码，差不多1300行代码(*源码只有200多行*)，本想把这混淆后的代码全部还原的，但是笔者JavaScript水平实在太差，实力不太允许，所以只能通过动态调试来获取关键信息，把算法逻辑猜出来。  

#### 1.3 本地动态调试  

如果直接访问目标站点进行调试，因受资源加载和网络等不可控因素影响，调试起来不是那么顺畅，也不清楚是否存在其他防调试手段干扰调试结果，并且可以判断出签名算法在sign.js中，所以我们可以考虑直接在本地运行sign.js，并对其进行调试，逆出sign参数的摘要算法。  
静态简单分析下sign.js文件中发现有define关键字，同时在search.html页面发现是使用的RequireJS框架加载模块。把站点使用的requirejs版本源码保存在本地，新建个html页面，根据requirejs语法规范加载本地格式化后的sign_format.js，然后分析数据包，构造一个符合规范的postData并调用s函数计算sign签名值:  

![](/assets/images/2019-12-25-js-decrypt/12.png)  

本地工程目录结构如下  

![](/assets/images/2019-12-25-js-decrypt/13.png)  

使用Chrome打开test.html，过程很顺利，sign值被正常计算:  

![](/assets/images/2019-12-25-js-decrypt/14.png)  

因为笔者实力不允许直接把混淆加密后的JS代码还原，所以就只能依靠Chrome强大的调试功能动态分析代码逻辑，先本地修改下sign_format.js中防调试部分的代码逻辑，让1238行if判断恒为真，然后一步一步的开始调试，看看sign签名是如何被计算出来的。  
首先在test.html调用s函数处断点，然后F11步入sign_format.js的入口点:

![](/assets/images/2019-12-25-js-decrypt/15.png)  

通过调试，发现首先会把postData和一段字符串拼接成一个新字符串  

![](/assets/images/2019-12-25-js-decrypt/16.png)  

接着将加盐的新字符串使用md5算法计算数据摘要  

![](/assets/images/2019-12-25-js-decrypt/17.png)  

至此，通过强大的Chrome调试工具，我们把sign.js混淆加密后的算法逻辑调试出来了，肯定有同学疑问是怎么判定的md5算法，见上图console输出的变量，`1732584193`、`-271733879`、`-1732584194`、`271733878`是MD5算法固定的4个链接常量，写段代码验证下:  

![](/assets/images/2019-12-25-js-decrypt/18.png)  

### 2. Hook技术对抗加密混淆  

虽然sign.js源码被混淆加密了，无法直接分析代码获取到sign签名值到的算法，但是我们知道，无论代码如何加固，在浏览器解析运行代码时，加密的代码总会还原成原始功能的代码，所以借助Chrome强大的调试工具，直接正面硬刚，最后肯定能破解的，只是如果混淆的算法复杂并存在多处反调试检测，那就会让分析的时间成本无限增加，有没有什么办法可以不去分析混淆加密后的代码，又能实现随意修改数据报文呢？答案就是利用Hook技术的思想。  

#### 2.1 什么是Hook  

Hook技术又叫钩子函数，在系统没有调用该函数之前，钩子程序就先捕获该消息，钩子函数先得到控制权，这时钩子函数既可以加工处理（改变）该函数的执行行为，还可以强制结束消息的传递。简单来说，利用hook技术可以随意干预程序的执行过程。  
在前言部分，笔者说过不太清楚是否有现成的hook框架可以动态修改浏览器JS的行为，既然不知道现成的框架在哪，那...笔者肯定也没实力自己写出一个框架来，但是可以利用Hook技术的思想来实现我们的需求。  

#### 2.2 定位Hook点  

在动态调试的分析过程中，知道sign签名值是在sign.js中计算的，调用加密函数s()的代码在search.html中，具体位置如下:  

![](/assets/images/2019-12-25-js-decrypt/19.png)  

如果在第10行调用s函数的前一刻，我们能控制传入的`postData`值，使传入s函数的数据已经是被修改过的，那不就可以不必去分析s加密函数的算法逻辑了吗？  

#### 2.3 Hook实现  

因为浏览器执行的JS代码是从服务端请求的，在JS代码从服务端下载到本地的过程中又是可以被拦截修改的，所以可以通过修改服务端返回的JS代码，在search.html的第10行之前插入Hook代码，把postData数据转移出来，等数据被修改之后再还回去，这样程序再调用s函数计算出的sign签名值就已经是被修改过后的数据的签名。  
在这个过程中，要把postData转移出来并修改它，可以通过在本地搭建个Web服务器，然后在search.html中插入Hook代码发送http请求，请求参数是`postData`，然后本地Web Server再把修改后的参数原样返回，接着将原来的postData更新成Web Server返回的数据，最后让程序自己调用s函数计算被修改后的数据签名值并执行后续代码逻辑。在这个实现中，我们需要解决5个问题:  

1. 如何在search.html中插入Hook代码；  
2. 修改数据时需要暂停后续代码执行的同步问题；
3. Hook代码发送http请求的跨域问题；
4. 协议不同造成的Mixed Content问题；  
5. 如何在最小改动下插入Hook代码；  

第一个问题，动态修改服务端返回的JS代码比较容易，可以利用burpsuite工具的proxy模块提供的Match and Replace功能。  
第二个问题，因为需求是Hook出来的数据被修改之后，程序才能执行后续的代码，所以在hook时，需要原程序先暂停执行。这里hook修改数据是使用http请求发送数据包，Fetch API虽然发送http请求非常简捷，但是只支持异步请求且不好给其他变量赋值，所以需要使用传统的XMLHttpRequest发送同步请求。  
第三个问题，浏览器同源策略造成的跨域限制是个比较坑的问题，问题本身不太好解决，但是可以通过设置Chrome启动参数`--disable-web-security`关闭同源策略。  
第四个问题，默认情况下，https页面不允许从http链接里面引用内容，虽然可以通过搭建一个支持https协议的Web Server解决问题，但还是没有直接通过设置Chrome启动参数`--allow-running-insecure-content`关闭限制来的方便。  
第五个问题，在寻找Hook点时，发现最佳Hook点在return语句中，并使用了逗号运算符，为了避免原代码篡改过多引出其他问题，通过创建自调用的匿名函数实现XMLHttpRequest。  

具体实现如下，创建自调用的匿名函数，实现XMLHttpRequest同步请求:  

![](/assets/images/2019-12-25-js-decrypt/20.png)  

本地搭建个Web Server，Response响应值就是Request请求内容  

![](/assets/images/2019-12-25-js-decrypt/21.png)  

使用终端启动一个关闭安全策略的Chrome浏览器  

```
open -n /Applications/Google\ Chrome.app/ --args --disable-web-security --allow-running-insecure-content --user-data-dir=/Users/memory/MyChromeDevUserData
```

设置浏览器代理成Burp监听端口，把Hook代码压缩成1行，利用burp的Match and Replace功能动态插入Hook代码:  

![](/assets/images/2019-12-25-js-decrypt/22.png)  

如果有本地缓存，无法重新获取js插入hook代码，可以打开Chrome开发者工具，勾选NetWork标签下的Disable cache选项，刷新页面就会从服务端重新下载js  

![](/assets/images/2019-12-25-js-decrypt/23.png)  

访问目标站点，目标js自动插入了Hook代码，如下所示  

![](/assets/images/2019-12-25-js-decrypt/24.png)  

每个业务请求发出之前，数据报文都会先被发送到本地Web Server中，此时就可以通过代理拦截，对sign签名前的数据报文进行篡改，如下所示，把搜索内容从aaa修改成bbb  

![](/assets/images/2019-12-25-js-decrypt/25.png)  

每个业务会拦截到2个请求（Hook请求192.168.1.7和真实请求192.168.1.5），发送到服务端的真实请求数据确认被篡改，sign值为篡改后的数据签名:    

![](/assets/images/2019-12-25-js-decrypt/26.png)  


### 3. 脱机加载JS脚本  

在动态调试的时候，为了避免资源加载，网络环境等因素干扰调试过程，我们把相依赖的js都脱离出来，然后在本地搭建了调试环境，但运行环境依赖于浏览器，除了方便Debug调试以外，无法对JS代码的运行做过多的干预。假如JS代码可以独立于浏览器运行起来，比如加载运行在自己编写程序中，那是不是可以直接调用JS的加密函数，把JS的加密逻辑包含在我们自己的程序里面呢？JAVA JDK自带的js引擎可以帮助实现我们的需求。  
#### 3.1 需求分析  

先来捋一捋需求，为什么要自己写程序实现加载运行js脚本。在做安全测试的时候，会去抓取业务的数据报文进行分析，为了防止攻击者对数据报文进行篡改发起恶意请求，所以利用js脚本计算数据报文的消息摘要，如果攻击者对数据报文进行了篡改，就会导致签名值比对不成功，使请求处理失败，同时为了防止攻击者获取到js脚本中计算数据摘要的关键算法，又对js脚本进行了混淆加密。因为我们比较容易分析得到加密函数的调用入口，但不太容易对混淆加密的js脚本进行还原，所以希望能够在自己的程序中加载运行加密混淆过后的js，并调用它的加密函数，这样即使不知道消息摘要使用的具体算法和密钥，但是可以通过调用它对外的接口，计算出任意数据的消息摘要。比如常用的安全测试工具Burpsuite，如果编写的burp插件可以运行并调用加密混淆后的js脚本函数，那通过burp修改数据报文后，在发送给服务器的过程中，插件拦截到请求报文，可以自动重新计算修改后的数据报文的签名值并替换原始的签名，那不是比利用Hook修改数据报文更加方便稳定？  

#### 3.2 脚本引擎实现  

Java的Nashorn是JDK中自带的Script引擎，可以通过它加载运行js脚本，并支持Java层调用js脚本的函数。在本案例中，sign.js中使用了AMD规范，需要使用RequireJS来加载它，通过一番踩坑，最终还是实现了需求，具体就不再赘述，直接看代码:  

```java  
public class ExecuteScript {
    public static void main(String[] args) {
        //创建脚本引擎管理器
        ScriptEngineManager manager = new ScriptEngineManager();
        //获取指定名称的脚本引擎
        ScriptEngine engine = manager.getEngineByName("js");
        try {
            String path = ExecuteScript.class.getResource("").getPath();
            //只有jjs的-scripting模式才支持readFully，所以需要自己实现该函数
            //参考：https://stackoverflow.com/questions/27788356/readfully-not-defined-with-java-nashorn-javascript-engine
            engine.eval(new FileReader(path + "/js/readFully.js"));
            //require.js需要使用r.js替代
            engine.eval(new FileReader(path + "/js/r.js"));
            engine.eval(new FileReader(path + "/js/loader.js"));
            if (engine instanceof Invocable) {
                Invocable invocable = (Invocable) engine;
                String postData = args[0];
                //调用js中的加密算法实现加密逻辑
                Object result = invocable.invokeFunction("getSign", path,postData);
                System.out.println("sign==>" + result);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```  

loader.js实现如下  

```javascript
function getSign(path,postData) {
    var signValue = null;
    //sign模块必须使用绝对路径，否则r.js找不到
    require([path + '/js/sign.js'], function (s) {
        signValue = s(postData);
    });
    return signValue;
}
```  

最后打包成jar包，效果如下  

![](/assets/images/2019-12-25-js-decrypt/27.png)  

## 0x03 结语  

当遇到数据包报文被前端js二次加密，同时js本身又被混淆加固，为了能够正常分析数据报文，我们提出了3种破解方法对抗加固混淆后的算法逻辑。每种方法各有利弊，正面硬刚肯定是百战不殆的法子，只要肯打时耗战，那破解结果肯定是最完美的。Hook和脱机加载脚本是取巧的方法，具体实现需要看代码场景，如果关联过多的上下文，那在实现过程中可能会遇到各种各样的坑，不过搞技术嘛，不就是踩坑与填坑吗？笔者水平有限，如有更好的方法对抗JS加密，请多多指教和交流，文章内容如有错误的地方，还请不吝赐教。  

**References:**  

[JavaScript混淆安全加固](https://github.com/yacan8/blog/blob/master/posts/JavaScript%E6%B7%B7%E6%B7%86%E5%AE%89%E5%85%A8%E5%8A%A0%E5%9B%BA.md)  
[Riding the Nashorn: Programming JavaScript on the JVM](https://www.n-k.de/riding-the-nashorn/)  
[r.js](https://github.com/requirejs/r.js)  

**免责声明：本文内容仅供安全研究之用，请勿用于非法用途，读者将其信息做其他用途，由读者承担全部法律及连带责任，本人不承担任何法律及连带责任。**  
**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**

{%endraw%}  