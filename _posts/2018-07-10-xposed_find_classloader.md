---
layout: post
title: 利用xposed插桩,获取真实ClassLoader的常见应用场景
date: 2018-07-10 14:30:35 +0800
categories: 移动安全
tag: Xposed
---

* content
{:toc}

{%raw%}


平时在使用xposed对代码插桩获取程序执行详情时,正常情况下直接利用系统的Classloader就能完成我们的需求.但是在一些特殊情况,比如APP被加固、动态加载dex等特殊情况,直接使用默认的classloader去hook就会发现达不到我们想要的效果,系统会报错`ClassNotFoundException`.下面对获取类对象对应的真实classloader的几种常见情况做个总结,以备后忘.  

## 0x01使用360加固  

使用360加固后的应用的classloader会被换成360自己的,所以在hook的时候需要把classloader替换成360的.  

#### 代码特征  
被360加固的应用反编译之后dex里面只有很少的几个类.比较重要的就是StubAppxxxx这个类（xxxx是一串数字）.可以在这个类里面的getNewAppInstance里面去获取context参数,然后就可以通过context获得到360的类加载器,之后只需要用这个类加载器来hook就可以成功的hook到360加固的app.  

![](/assets/images/2018-07-10-xposed_find_classloader/1.png)  

#### 示例代码  

```java
		//hook 360壳  
		XposedHelpers.findAndHookMethod("com.qihoo.util.StubApp579459766", loadPackageParam.classLoader,"getNewAppInstance", Context.class, new XC_MethodHook() {
        	@Override
        	protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            	super.afterHookedMethod(param);
            	//获取到360的Context对象，通过这个对象来获取classloader
            	Context context = (Context) param.args[0];
            	//获取360的classloader，之后hook加固后的代码就使用这个classloader
            	ClassLoader classLoader =context.getClassLoader();
            	//替换classloader,hook加固后的真正代码
            	XposedHelpers.findAndHookMethod("xxx.xxx.xxx.xxx", classLoader, "xxx", String.class, String.class, new XC_MethodHook() {
                	@Override
                	protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    	super.beforeHookedMethod(param);
                    	Log.d(TAG, "==>0 " + param.args[0].toString());
                        Log.d(TAG, "==>1 " + param.args[1].toString());
                  }
              	});
            }
        });

```  

##  0x02 使用百度加固  

原理同360,classloader被替换了,所以需要把xposed获取到的classloader替换成百度的.  

#### 代码特征  

被百度加固的APP,直接反编译也只能看到外层壳的代码.包名特征是com.baidu.xxx,可以通过hook StuApplication的onCreate方法获取真实的类加载器,然后再拿classloader去hook真实的逻辑代码.  

![](/assets/images/2018-07-10-xposed_find_classloader/2.png)  

#### 示例代码  

```java
		//hook 百度壳
        XposedHelpers.findAndHookMethod("com.baidu.protect.StubApplication", loadPackageParam.classLoader, "onCreate", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Application appClz = (Application) param.thisObject;
                //通过onCreate执行完毕后,获取结果对象的classloader
                ClassLoader loader = appClz.getClassLoader();
                //替换classloader,hook加固后的真正代码
                XposedHelpers.findAndHookMethod("xxx.xxx.xxx", loader, "xxx",  String.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "==>0 " + param.args[0].toString());
                        Log.d(TAG, "==>1 " + param.args[1].toString());
                    }
                });
            }
        });

```  

## 0x03 使用其他加固  

思路还是一样的,在hook目标代码之前,需要获取到加载该代码的真实classloader.一般是去hook应用的入口attachBaseContext或者onCreate,然后再拿到before的Context参数或者after的结果,再强制转换成classloader对象.  

#### 代码特征  

加固后的APP,在使用工具反编译后,一般只能看见几个类方法.核心的关键代码都看不见.加固特征如下.  

![](/assets/images/2018-07-10-xposed_find_classloader/3.png)  

#### 示例代码  

```java
		//获取加固APP的classloader,一般在attachBaseContext或者onCreate入口开始分析
		XposedHelpers.findAndHookMethod("com.shell.SuperApplication", lpparam.classLoader, "attachBaseContext",Context.class, new XC_MethodHook() {
			@Override
			protected void afterHookedMethod(MethodHookParam param) throws Throwable {
				//获取壳的Context对象,通过该对象获取classloader
				Context context = (Context) param.args[0];
				//获取Context的classloader
				ClassLoader classLoader = context.getClassLoader();
				//替换classloader,hook加固后的真正代码
				XposedHelpers.findAndHookMethod("xxx.xxx.xxx", classLoader, "xxx", String.class,String.class, new XC_MethodHook() {
					@Override
					protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
						Log.d(TAG, "==>0 " + param.args[0].toString());
                        Log.d(TAG, "==>1 " + param.args[1].toString());
					}
				});
			}
		});

```  

## 0x04 使用DexClassLoader动态加载jar/apk  

在平时逆向APP时,发现部分应用会使用动态加载插件的技术.一般是在应用启动时,从服务器下载最新的插件包(通常是个jar包),然后APP在运行到具体业务时,再利用DexClassLoader加载插件包(jar/apk里面的dex)然后运行其字节码.  

#### 代码特征  

使用DexClassLoader动态加载dex,下图传入loadParser方法的3个参数分别是:  
arg5:Context  
arg6:插件jar包的绝对路径  
arg7:需要加载的jar中的类全名

![](/assets/images/2018-07-10-xposed_find_classloader/4.png)  

DexClassLoader (String dexPath,String optimizedDirectory,String libraryPath,ClassLoader parent)方法的4个参数分别是:  
dexPath:指目标类所在的jar/apk文件路径  
optimizedDirectory:解压出的dex文件的存放路径  
libraryPath:目标类中的C/C++库存放路径。  
parent:父类装载器  

#### 示例代码  

使用类加载器动态加载插件,最后都会调用java.lang.ClassLoader的loadClass去加载具体的字节码.所以可以通过hook系统函数loadClass获取真正的classloader.(理论上加固的app也可以直接通过hook该函数拿到对应的classloader)  

```java
 	@Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
    	//hook系统的类加载器来获取classloader
    	XposedHelpers.findAndHookMethod("java.lang.ClassLoader", loadPackageParam.classLoader, "loadClass", String.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            	//可以通过需要hook的目标类全名过滤一下
                //if("xxx.xxx.xx.xx".equals(param.args[0])){
                	//1.可以通过xposed的thisObject获取加载的当前对象然后强制转换成classloader
                    //ClassLoader loader = (ClassLoader) param.thisObject;
                    //2.也可以先获取类加载的结果Class对象,然后再获取class的classloader
                    Class clz = (Class) param.getResult();
                    ClassLoader loader = clz.getClassLoader();
                    //利用获取的真正classloader,hook jar/apk中的方法
                    XposedHelpers.findAndHookMethod("xxx.xx.xx.xxx", loader, "xxx", String.class, new XC_MethodHook() {

                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Log.d(TAG, "jar hook success...");
                            Log.d(TAG,param.args[0].toString());
                        }
                    });
           //   }
            }
        });
    }

```  

## 0x05 动态加载的其他情况  

上面动态加载示例在它loadClass后,继续newInstance实例化了一个对象,然后调用对象的某方法,最后返回该对象方法的值(示例返回UrlParser对象),而返回的对象不能强制转换成ClassLoader对象,所以才需要去hook系统的loadClass方法.  
而有些产品在插件化的实现中,可能会在某个方法里面实现自己的classloader去加载jar/apk插件.这种情况就直接hook该方法,在after里面获取classloader就行了.(类似加固APP在外层壳获取classloader).


**References:**  

[Android动态加载——DexClassloader分析](http://www.jianshu.com/p/669fc4858194)  
[Android插件化探索（一）类加载器DexClassLoader](http://blog.csdn.net/maplejaw_/article/details/51493843)  
[ClassLoader源码](http://androidxref.com/5.1.0_r1/xref/libcore/libart/src/main/java/java/lang/ClassLoader.java)  
[使用xposed来hook使用360加固的应用 ](https://www.52pojie.cn/thread-534126-1-1.html)  

**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}