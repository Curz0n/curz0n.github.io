---
layout: post
title: 利用burp插件和Xposed实现Android APP数据包加解密
date: 2016-10-28 10:45:56 +0800
categories: 移动安全
tag: Android Sec
---

* content
{:toc}

{%raw%}


## 0×00 前言

刚从WEB端安全测试转到Android移动端，因为Android的后端Serve和WEB端大致一样，移动是直接调用的WEB接口去实现各种业务功能，所以面临的危害也和WEB一致，比如可能被中间人攻击劫取流量、注入等问题。所以在测试的时候第一步当然还是抓包看看数据结构，谁知道抓到的数据包结果竟然长下面这个模样：<span id="jump1"></span>  

>POST /\*\*/\*\*/sendCookie HTTP/1.1  
>device-type: Android  
>Content-Type: application/x-www-form-urlencoded  
>User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; MI MAX MIUI/6.10.13)  
>Host: \*\*.\*\*.com  
>Connection: close  
>Accept-Encoding: gzip  
>Content-Length: 655  
>
>**input**=Lt8A5mWNWUuSIRlrKlekxBHj17ZWZS3zssKV9a4Bcj4R12unhU1CgMgx%2Fdk9ITUekerqkzZ723YeX7rbw1peyNX24I7OPq7C7qAMJZOKiiRV7oJiO9R9kqJPzJeIIAfS9iigL%2B5NdphB%2B8Zk%2Bx0E4JibrQECJcfcWYx1gMPS1fbES1Ukro0JDeNyeSKCTz4sTDhA1XP4FVt6InOB26Tbpld35%2BBAAXT5PWsOT7UmPFAYQZrRZ5FYJ6XG1Mn%2BenXGH%2F6fdL3fDCnw%2FXe2CWR8UALXzUL6FUkSJPn3zMI63Bl8JW1qqmvsd%2FZqbaGKzZtZuxDwqMYiZoJCdMwZkJK1aAxNClmaYshnypCtZfct7ABXn3N5mNfAOFmgt3KhgBuEAnvbajdGNrKroSUCKtjuPw%3D%3D&**checkSign**=idX5gZKZyIuSs2zFbXiIBSCfgyn5ShZrNEOAnM7XA1kDhnbBVaA8dlTXwwa5Fp%2BDapeXYZnWbsD32fl%2BZUwD193Pi%2B%2BNMszFWN7cCzFu61pszjvAjvuc0OgGcZMkCnmtQ3pbNwWhOJRTV1rE%2F1COcSWqeuA7EHe6LO2GgykATDg%3D&**method**=requestUserLogin  

很明显从参数method的值可知这就是登录的请求包，但是输入的用户名、密码却不像传统web一样是明文。对该POST请求参数稍加分析可知，用户密码等值应该就是包含在input参数里面的。但是参数长这个模样，不能跟传统web一样直接改包测试。为了进一步渗透，显然需要对这个加密过后的数据包进行还原处理。  
本文将主要介绍如何还原加密过的HTTP(S)数据包并对数据包进行篡改，然后再对篡改过后的数据包进行加密还原，最后再发给服务器。过程中可能涉及APK逆向分析以及其他第三方工具的使用，本文不对这部分做详解介绍，重点只关注如何实现对加密包的解密并还原加密。  

## 0×01 把数据包还原成明文

### 1.过程分析  

要对数据包进行还原，首先需要搞清楚的是数据在什么时候被加密的，很显然数据在进入burpsuite代理之前就已经被处理过了。第一步要做的就是对APK反编译，分析数据在手机屏幕输入到APP发送请求的这一段过程中APP究竟对它做了些什么处理。幸运的是很快定位到了如下两行关键代码：<span id="jump2"></span>

```java
    arg6.put("input", v0_1.encrypt(((String)v1_1), v2));
    arg6.put("checkSign", v0_1.encryptByPublicKey(v2, "NADCBiQKBgQC4a28EvilEbKEnwy3n7iPaZeZIVlSF9L6IOb9mbm8NVSC8HUtJgpdnvCkGzJc/TJ7Rm3geZIXK84dh/Dgl5zOh8voJgMGc66bDQ+RbYpnkH8FpthwdknTQlJB"));
```

从代码可知，输入的参数最终会被一个叫`encrypt()`的函数处理，继续查看该函数。`encrypt()`代码详情如下：<span id="jump"></span>

```java
    public String encrypt(String arg7, String arg8) {
        String v0_9;
        __monitor_enter(this);
        try {
            SecretKeySpec v0_8 = new SecretKeySpec(arg8.getBytes(), "AES");
            Cipher v1 = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] v2 = arg7.getBytes("utf-8");
            v1.init(1, ((Key)v0_8), new IvParameterSpec("0000000000000000".getBytes()));
            v0_9 = Base64.encodeToString(v1.doFinal(v2), 2);
        }
        catch(Throwable v0) {
        }
        catch(InvalidAlgorithmParameterException v0_1) {
        }
        catch(BadPaddingException v0_2) {
        }
        catch(IllegalBlockSizeException v0_3) {
        }
        catch(UnsupportedEncodingException v0_4) {
        }
        catch(InvalidKeyException v0_5) {
            try {
                v0_5.printStackTrace();
                goto label_22;
                v0_4.printStackTrace();
                goto label_22;
                v0_3.printStackTrace();
                goto label_22;
                v0_2.printStackTrace();
                goto label_22;
                v0_1.printStackTrace();
            label_22:
                v0_9 = null;
            }
            catch(Throwable v0) {
            label_28:
                __monitor_exit(this);
                throw v0;
            }
        }
        catch(NoSuchPaddingException v0_6) {
        }
        catch(NoSuchAlgorithmException v0_7) {
            try {
                v0_7.printStackTrace();
                goto label_22;
                v0_6.printStackTrace();
                goto label_22;
            }
            catch(Throwable v0) {
                goto label_28;
            }
        }

        __monitor_exit(this);
        return v0_9;
    }

```

到这里先说明下代码的逻辑：用户输入的账号密码会和其他参数（比如软件版本信息等）先封装成一个json格式的字符串，也就上面代码中的`(String)v1_1`参数，然后通过MAP形式的键值对将参数(v1_1)赋给`input`这个`Key`，而在赋值之前这段字符串(v1_1)会先传入一个叫`encrypt()`的函数使用AES加密处理，然后将处理结果数据返回，最终赋值给`input`，最后再发送给服务器。具体看流程图如下：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161028163501.png)  
所以如果能够绕过`encrypt()`加密函数，那burpsuite代理不就抓取的是明文数据包了吗？

### 2.Xposed模块实现数据解密  

什么是Xposed？**Xposed框架是一款可以在不修改APK的情况下影响程序运行(修改系统)的框架服务。**很牛逼！向开发此框架的大牛致敬！=.=  
废话不多说，这里只需要用到Xposed模块最基本的功能，对目标函数插桩。  
新建一个xposed工程，实现`IXposedHookLoadPackage`接口，重写`handleLoadPackage`方法，在该方法中再调用`findAndHookMethod`方法，这个方法中有个参数`XC_MethodHook`是对象，直接实例化该对象，覆写对象里面的`beforeHookedMethod`和`afterHookedMethod`方法。具体实现代码看下面，注释写的比较清楚了：

```java
public class Module implements IXposedHookLoadPackage{

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        // 判断hook对象的包名是否正确
        if (!lpparam.packageName.equals("com.**.**.personal")) {
            Log.d("Hook", "not found package");
            //XposedBridge.log("not found package");
            return;
        }
        // 找到hook的类名和函数
        XposedHelpers.findAndHookMethod("com.**.**.**.util.**", lpparam.classLoader, "encrypt",
                String.class, String.class, new XC_MethodHook() {

                    // 在正常函数调用之前执行
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d("Hook_befor", "加密前：" + (String) param.args[0] + "---->key:" + (String) param.args[1]);
                    }

                    // 在正常函数调用之后执行
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult((String) param.args[0]);
                        Log.d("Hook_after", "加密后1：" + (String) param.getResult() + "---->key:" + (String) param.args[1]);
                    }
                });
    }

}
```

加载该Xposed模块，通过DDMS查看效果如下图：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161028231655.png)  
接下来解释一下Module代码执行逻辑以及Logcat打印的日志信息。  
首先自己写的`Module`类实现`IXposedHookLoadPackage`接口，`handleLoadPackage`方法是在被Hook的应用启动之后调用，`findAndHookMethod`就是一个普通的方法，它里面有一个对象`XC_MethodHook`是一个监听器，监听被Hook的方法是否被调用，然后这里面有两个状态，一个是`beforeHookedMethod`另一个是`afterHookedMethod`。`beforeHookedMethod`会在函数被Hook前调用，`afterHookedMethod`会在被Hook之后调用。另外`findAndHookMethod`还有一个参数`methodName`，代表需要Hook的方法名。这里需要Hook的方法就是AES加密函数`encrypt`。  
说了这么久的Hook是什么意思呢?英文翻译过来是挂钩的意思。通俗点讲**Hook一个方法就是获取传入这个方法之前的参数原值和经过这个方法处理过后return的值**。  
结合上述实例，因为目标是获取加密之前的明文值，而burp代理抓到的数据是经过加密过后的数据。这个数据的加密过程就是通过`encrypt`方法实现的，所以在参数传入`encrypt`方法之前数据还是明文的，经过函数处理过后就变成密文了。Xposed模块里面的`beforeHookedMethod`方法就是获取（Hook）传入`encrypt`加密函数之前的原值，`afterHookedMethod`是获取经过`encrypt`函数处理过后return的密文。所以由上图Logcat的日志可以看见红框圈出的数据(传入encrypt之前的数据)是明文。那为什么loginPasswd参数值是密文？请不要在意这些细节，因为password属于特别敏感的数据，所以它做了2次加密，而这个字段只有在登录的时候会出现，对于测试影响不大，所以不是特别特殊的情况下可以先忽略。而其他的关键字段如userName已经被明文显示出来了。刚才不是说`afterHookedMethod`Hook出的数据是经过`encrypt`处理加密过后的数据吗？为什么日志打印的数据和加密前数据一样呢？提出这个疑问之前请返回去看看Xposed的代码。`afterHookedMethod`方法中这么一句代码：  

```java
param.setResult((String) param.args[0]);
```

这句代码作用就是获取传入`encrypt`函数之前的原始数据，然后将它赋值给`encrypt`方法return的返回值。效果就变成了传入`encrypt`之前的原值和`encrypt`加密后的值相等，也就是说它让`encrypt`加密函数失效了。看下面流程图。  
本来正常Hook数据打印的日志应该是这样的：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161029003034.png)  
但是我们将`afterHookedMethod`Hook到的结果数据篡改了，所以变成了下面这样：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161029004117.png)  
验证一下，burp抓个包：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161029004449.png)  

## 0×02 将明文数据包还原成加密状态  

通过Xposed模块已经可以使Burpsuite抓到明文包，并对数据进行篡改了。但是如果直接将明文包发送给服务器，那服务器肯定不能正确解密的。所以接下来的工作就是对明文包进行加密还原，使服务器能够正确解密。  

### 1.开发Burpsuite插件加密数据包   

开发burp插件，其实就是使burp的插件重新实现APK里的加密逻辑，将APK里面的加密函数“Copy”到burp插件中去就行了。当然这里的Copy肯定不是简单的Ctrl+C和Ctrl+V的过程，至少大部分不是这样的。因为APK反编译出来的Java代码并不是真正的源码，如[上面的`encrypt()`](#jump)方法里的代码，只能看懂大概逻辑，如果直接将它复制到Java工程中，肯定是不能运行的。况且有很大部分APK被做了防反编译或者加固，根本不能反编译成Java代码，这个时候只能通过看smali代码然后再翻译成java代码。甚至有些APP的加密函数写在so动态库的，这个时候更需要去读汇编或C代码，如果APK被加固，那还涉及脱壳等等。还有更头疼的是有些加密算法是产品参考业界加密算法改写的，然后加上自己的特征。这个时候如果再将它放入so库加混淆什么的。嗯，扯远了点...当然从本次案例来看还是很幸运的，可直接反编译成逻辑较清晰的Java代码，而且重现起来也不是很复杂。  
新建一个Java工程，创造一个用于加密数据的类，类名是`AESCrypt`，然后将[`encrypt()`](#jump)函数里面的逻辑重写，如下：  

```java
    public String encrypt(String parameter, String key) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher instance;
        String enString = "";
        try {
            instance = Cipher.getInstance("AES/CBC/PKCS7Padding");
            instance.init(1, secretKeySpec, new IvParameterSpec("0000000000000000".getBytes()));
            byte[] bytesPar = parameter.getBytes("utf-8");
            enString = Base64.encodeToString(instance.doFinal(bytesPar), 2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return enString;
    }
```

重写这个方法比较简单，因为反编译回来的代码并没有做混淆。接下看看这个函数的处理逻辑，当调用`encrypt()`方法的时候，传入两个参数，一个是需要被加密的字符串，还有一个是AES加密时需要的KEY。然后使用AES加密算法的CBC模式，填充方式是PKCS7Padding对数据进行加密。最后将AES加密的数据Base64编码，然后`return`。逻辑很清晰，这里需要注意的问题只有两个：  
第一个，Android里面是支持`PKCS7Padding`这种填充方式的，但是Java只支持`PKCS5Padding`。将它移植到Java中需要引用第三方Jar扩展包来解决，具体详情可[戳这里](http://blog.csdn.net/m1mory/article/details/52939126)参考我在CSDN博客的问题记录。  
第二个需要关注的是KEY，通过分析代码最后发现这个KEY是随机生成的，即每次发送的数据包，AES加密使用的KEY都不一样，所以造成同一个字符串每次burp抓到的数据包都不同，是动态变化的，挺有意思的。生成KEY的代码如下：  

```java
    public static String a(int arg5) {
        String v1 = "0123456bcdefghijklmnopqrstuvwEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuffer v2 = new StringBuffer();
        Random v3 = new Random();
        int v0;
        for(v0 = 0; v0 < arg5; ++v0) {
            v2.append(v1.charAt(v3.nextInt(v1.length())));
        }

        return v2.toString();
    }
```

生成KEY的这段代码就不多废话了，知道AES加密算法的朋友肯定会奇怪，AES是对称加密，加密秘钥和解密秘钥是同一个KEY，那这里客户端动态生成KEY，使它每次都在变化，服务器怎么会知道它每次加密使用的KEY是什么呢？如果不知道，那服务器怎么对加密字符解密呢。细心的盆友肯定早已发现，在[开篇](#jump1)贴出来的请求数据包中，POST请求参数中还有一个参数——`checkSign`。其实这个参数的值就是每次AES加密使用的随机生成的KEY。但是，这个`checkSign`的值也是一个密文。  
就不绕弯子了，还记得最开始贴出来的2行代码吧，那是整个分析的切入点，忘记的[请戳这里](#jump2)，这里的第二句代码就是对每次随机生成的KEY的处理，它会被传入一个叫`encryptByPublicKey`函数里。这个函数里面使用的是RSA非对称加密，RSA对数据加密和解密使用的KEY都是不同的，所以这里就保证了AES的KEY发往服务器过程中的安全性。具体`encryptByPublicKey`的反编译代码如下：

```java
    public String encryptByPublicKey(String arg11, String arg12) {
        int v2_1;
        ByteArrayOutputStream v5;
        int v4;
        Cipher v3;
        int v8 = 117;
        int v1 = 0;
        __monitor_enter(this);
        String v0 = null;
        try {
            PublicKey v2 = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(arg12.getBytes(), 0)));
            v3 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            v3.init(1, ((Key)v2));
            v4 = arg11.getBytes().length;
            v5 = new ByteArrayOutputStream();
            v2_1 = 0;
        label_21:
            while(v4 - v1 <= 0) {
                goto label_23;
            }
        }
        catch(Throwable v0_1) {
            goto label_51;
        }
        catch(Exception v1_1) {
            goto label_48;
        }

        if(v4 - v1 > v8) {
            try {
                byte[] v1_2 = v3.doFinal(arg11.getBytes(), v1, 117);
                goto label_34;
            label_43:
                v1_2 = v3.doFinal(arg11.getBytes(), v1, v4 - v1);
            label_34:
                v5.write(v1_2, 0, v1_2.length);
                v1 = v2_1 + 1;
                int v9 = v1;
                v1 *= 117;
                v2_1 = v9;
                goto label_21;
            label_23:
                v1_2 = v5.toByteArray();
                v5.close();
                v0 = Base64.encodeToString(v1_2, 2);
                goto label_27;
            }
            catch(Throwable v0_1) {
            label_51:
                __monitor_exit(this);
                throw v0_1;
            }
            catch(Exception v1_1) {
                try {
                label_48:
                    v1_1.printStackTrace();
                }
                catch(Throwable v0_1) {
                    goto label_51;
                }

            label_27:
                __monitor_exit(this);
                return v0;
            }
        }
        else {
            goto label_43;
        }

        goto label_34;
    }
```

这个函数在Java代码里面重写就比`encrypt()`稍微复杂点了，因为反编译回来的代码里面有goto跳转，幸在代码逻辑不太复杂，整理后的代码如下：  

```java
    public String encryptByPublicKey(String parameter, String key) throws Exception {

        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.decode(key.getBytes(), 0)));
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(1, publicKey);
        int keyLength = parameter.getBytes().length;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int i = 0;// v1
        int j = 0;// v2_1
        byte[] doFinal;// v1_2
        String baseStr = null;
        
        if (keyLength - i > 117) {
            doFinal = instance.doFinal(parameter.getBytes(), i, 117);
        } else {
            doFinal = instance.doFinal(parameter.getBytes(), i, keyLength - i);
            outputStream.write(doFinal, 0, doFinal.length);
            i = j + 1;
            int k = i;// v9
            i *= 117;
            j = k;
            while (keyLength - i <= 0) {
                doFinal = outputStream.toByteArray();
                outputStream.close();
                baseStr = Base64.encodeToString(doFinal, 2);
                return baseStr;
            }
        }
        return baseStr;
    }
```

可以看到调用`encryptByPublicKey`函数的时候也传入了两个参数，一个是待加密的AES的KEY，另外一个是RSA加密AES KEY所需要的KEY。RSA的KEY是公钥，分析反编译的代码就能找到它，并且它肯定是固定的。下面再画一个图，捋一捋整个加密的过程：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161029112047.png)  
到这里APK里面的整个加密过程已经完全移植到burp插件中去了，这里再补充下数据包发送到服务器后服务器的解密过程：  
当POST密文数据包发送到服务器后，服务器先用RSA私钥对checkSign解密，拿到AES秘钥，然后使用AES秘钥对input解密，最终完成数据的交互过程。整个过程很清晰，而且个人觉得安全性考虑的也比较周到了，如果在APK里将加密函数"藏"起来，那就更加完美了。  
剩下的就是常规的Burp插件开发，具体开发教程请Google或查阅官方API，这里不做详细介绍。另外笔者整理了份burp插件开发中文API CHM帮助文档，有兴趣的朋友[戳这里](http://download.csdn.net/detail/m1mory/9666236)下载。下面是burp插件核心逻辑代码：

```java
public class BurpExtender implements IBurpExtender, IHttpListener {
    
    private PrintWriter stdout;//输出日志
    private IExtensionHelpers helpers;//工具类

    /// 在插件加载后调用
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName("Test Extends");
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        // 注册一个http监听器，burp发起的每个http请求或者收到的响应都会通知此监听器。
        callbacks.registerHttpListener(this);
    }
    
    // 实现此接口，获取所有http数据包
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // True:代表是request
        if (messageIsRequest) {
            // 获取http请求信息
            byte[] requestBytes = messageInfo.getRequest();
            //获取http服务，方便拿到host
            IHttpService httpService = messageInfo.getHttpService();
            String host = httpService.getHost().trim();
            //得到一个请求的详细信息（该对象可以对请求参数做细化处理）
            IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
            stdout.println("host--->"+host);
            if(host.equals("**.**.**.90") || host.equals("**.**.com")){
                String input = "";
                String checkSign = "";
                //获得请求中包含的参数
                List<IParameter> parameters = analyzeRequest.getParameters();
                //遍历参数
                for (IParameter iParameter : parameters) {
                    if(iParameter.getName().equals("input")){
                        input = iParameter.getValue();
                        //将获取的参数值url解码
                        input = helpers.urlDecode(input);
                        //对取出来的明文值做加密处理
                        AESCrypt aesCrypt = new AESCrypt();
                        String key = aesCrypt.key(32);//AES随机生成的KEY
                        String RSAKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4a28EvilEbKEnwy3n7iPaZeZIVlSFaXpklWikHJ8WwL+Y5Omb9mbm8NVSC8HUtJgpdnvCkGK84dh/Dgl5zOh8voJgMGc66bDQ+RbYpnkH8FpthwdknTQlJ2AyDr7BwIDAQAB";
                        try {
                            input = aesCrypt.encrypt(input, key);
                            checkSign = aesCrypt.encryptByPublicKey(key, RSAKey);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        //将加密后的参数做url编码
                        input = helpers.urlEncode(input);
                        checkSign = helpers.urlEncode(checkSign);
                        //更新请求参数
                        IParameter buildParameter = helpers.buildParameter("input", input, iParameter.getType());
                        //更新http请求包(转换成byte[])
                        requestBytes = helpers.updateParameter(requestBytes, buildParameter);
                        buildParameter = helpers.buildParameter("checkSign", checkSign, iParameter.getType());
                        requestBytes = helpers.updateParameter(requestBytes, buildParameter);
                        //发送请求
                        messageInfo.setRequest(requestBytes);
                        break;
                    }
                }
            }
        }
    }

}
```

写到这里，终于快结束了。整篇文章对Xposed模块开发以及burp插件开发等技术的细节没有做详细叙述，这些其实找Google就行了。最后，再画一幅图，看看从头到尾的一个数据包解密再二次加密的流程是怎样的：  
![](/assets/images/2016-10-28-burp_xposed_encrypt/20161029121326.png)

## 0×03 结语

第一次写技术博客，会有很多瑕疵，将就着看吧=.=  
对于这个案例，再补充一点，在burp实现加密函数的时候，完全是照着APK里面的逻辑处理的，如果遇到AES的Random Key函数比较特殊，不容易重现怎么办呢？因为只要加密数据时使用的AES Key和对AES Key加密后的RSA密文能正确对应，然后同时发给服务器，那服务器就能够正常解密的。所以思路可以转变下，AES的Key不需要随机生成，只需要开始Hook一个正确的明文KEY和RSA加密后的KEY或者自己随便写一个Key，使用RSA加密，然后将它们硬编码在插件代码中（一定要一一对应），这样服务器其实也能正确解码的。  
好了，通过这个案例，其实大部分Android客户端加密都能够应对了，复杂点的就像上文所述，加密函数写在so动态库里等等，这些需要一定的汇编基础，如果有机会，后边儿遇到了再分享吧。  
**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**

{%endraw%}