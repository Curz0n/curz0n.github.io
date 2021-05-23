---
layout: post
title: Android so层算法分析实战(一)
date: 2021-5-23 20:33:22 +0800
categories: 移动安全
tag: Android Sec
---

* content
{:toc}

{%raw%}  

## 0x00 前言  

某APP应用对数据报文做了签名校验，以防止中间人篡改数据报文。如下图所示，如果篡改数据包，则提示"非法请求"  

![](/assets/images/2021-05-23-android-so-reverse-frist/1.png)  

## 0x01 Java层分析  

通过分析数据包结构，可知请求头中的X-Sign字段作用是对数据报文进行签名，搜索关键字，可以非常容易的定位到关键代码  

![](/assets/images/2021-05-23-android-so-reverse-frist/2.png)  

进一步分析函数调用，发现sign是通过调用native方法NativeMakeSignature生成的  

![](/assets/images/2021-05-23-android-so-reverse-frist/3.png)  

objection打印一下参数，其中NativeMakeSignature方法的第二个参数为POST请求参数的Base64编码，返回值与报文中的X-Sign值一致。    

![](/assets/images/2021-05-23-android-so-reverse-frist/4_1.png)  

进一步分析MapiSign类，可知Static代码块中加载了`libMapiSign.so`，其native方法的具体实现应该就在该so文件中。  

## 0x02 SO静态分析  

IDA打开so文件，导出表中搜索一下，NativeMakeSignature方法是通过静态注册  

![](/assets/images/2021-05-23-android-so-reverse-frist/5.png)  

分析Java层的native方法，可知其函数原型为  

```c
JNIEXPORT jstring JNICALL Java_***_***_MapiSign_NativeMakeSignature
  (JNIEnv *, jclass, jstring, jstring);
```

将ida伪代码中的第一个参数类型改成`JNIEnv`，最后两个参数改成`jstring`类型，`Force call type`修复伪代码    

![](/assets/images/2021-05-23-android-so-reverse-frist/6.png)  

伪代码中a4重新赋值给了v4变量，存在冗余的代码，鼠标选中v4，按`快捷键=`，消除冗余代码，并对a4变量重命名，优化后的伪代码如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/7.png)  

先看sub_35638函数，这里调用了两次，分别将Java层传入的参数传入该函数。具体分析如下，sub_35330里面就是分配新内存，将传入的字符串拷贝到新内存中，具体代码就不贴了，a1（v4）指针保存返回值，其值为字符串的内存地址。  

![](/assets/images/2021-05-23-android-so-reverse-frist/8.png)  

可以hook sub_35638函数看一下，这里因为函数不是导出函数，所以需要根据偏移地址定位到函数，Frida脚本如下  

```javascript
//获取指定so的基地址  
var baseAddr = Module.findBaseAddress("libMapiSign.so");
//thumb状态，地址+1
var sub_35638Addr = baseAddr.add(0x35638 + 0x01);
Interceptor.attach(sub_35638Addr,{
    onEnter: function (args) {
    },
    //retval是返回值
    onLeave: function (retval) {
        //先获取指针存储的数值作为地址（字符串地址），然后再读取该地址中的值（字符串内容）
        console.log("0x35638 return: " + Memory.readPointer(retval).readCString());
    }
});
```  
可以看见从Java层传入的两个字符串值都原样返回，同时发现这里return了四个值，说明还有其他地方调用了该函数  

![](/assets/images/2021-05-23-android-so-reverse-frist/9.png)  

接着看makeSignature函数，从sub_35638函数返回的值（v12，v13）都传入了该函数，从函数名可以判断出sign算法的实现就在该函数中  

![](/assets/images/2021-05-23-android-so-reverse-frist/10.png)  

简单分析一下，可知被base64编码的post参数值赋值给v5，然后传入了genSignature函数，调用genSignature函数之前，有一个if判断，如果判断失败，则执行到42行，可以看见"parseSalt failed"提示。根据提示信息，可知在解析salt，分析第31行代码，调用parseSalt函数，传入parseSalt函数的dword_570A0变量在bss段，不好静态分析其值。然后看26或者36行的genSignature函数，均传入了dword_570A0和v5变量。进入genSignature函数，详情如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/11.png)  

分析代码可以明显看见有一个md5函数，在看其他代码之前，我们先看一下第23行的base64_encode函数，在最后return的时候，return值v3是调用sub_35638函数返回的  

![](/assets/images/2021-05-23-android-so-reverse-frist/12.png)  

通过前面hook的sub_35638返回值可知，一次请求调用了四次sub_35638，前两次是Java层传入的两个参数调用的，那第三次应该就是base64_encode函数最后return时调用的。base64解码看一下，解码后的值确实等于Java层传入的post编码值，说明base64_encode函数仅仅是对传入的值再次base64编码，并没有做其他操作  

![](/assets/images/2021-05-23-android-so-reverse-frist/13.png)  

同理，hook sub_35638函数的第四个返回值等于最终的sign值，那应该是在md5_encode函数里面最后调用的，查看md5_encode函数，return前确实调用了sub_35638函数函数，至此明白了Frida日志中为什么有四个return。    

![](/assets/images/2021-05-23-android-so-reverse-frist/14.png)  

接着分析，先hook md5_encode函数，看看传入的参数值是什么，Frida脚本如下，这里因为md5_encode函数是导出函数，所以可以根据函数符号进行hook  

```javascript
//md5
Interceptor.attach(Module.getExportByName("libMapiSign.so","_Z10md5_encodePKcb"),{
    //打印传入md5_encoe的三个参数值
    onEnter: function (args) {
        console.log("md5encode arg1 is: " + args[0].readCString());
        console.log("md5encode arg2 is: " + args[1].readCString());
        console.log("md5encode arg3 is: " + args[2].toInt32());
    },

    onLeave: function (retval) {
    }
});
```  

可以看见传入md5_encode的第二个参数和base64_encode返回的值似乎没什么关系，并且尾部还有一段类似Hash的字符串

![](/assets/images/2021-05-23-android-so-reverse-frist/15.png)  

先验证一下最后的sign值是不是arg2这段字符串计算的，通过验证，确认md5_encode函数直接对传入的arg2参数进行md5运算，并没有加盐和其他额外操作  

![](/assets/images/2021-05-23-android-so-reverse-frist/16.png)  

分析genSignature函数，看看base64_encode函数的返回值与传入md5_encode函数的第二个参数有什么联系。通过分析可知，base64_encode函数的返回值传入了第26行的drift函数，md5_encode函数的v8参数也与drift函数是v11有联系，进入drift函数，详情如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/17.png)  

传入drift函数的a2变量接着传入sub_352C0函数，且调用了两次，先hook下该函数，看看传入的参数值和返回值，Frida脚本如下  

```javascript
//sub_352C0
var sub_352C0Addr = baseAddr.add(0x352C0 + 0x01);
Interceptor.attach(sub_352C0Addr,{
    onEnter: function (args) {
        console.log("sub_352C0 Func arg1 is: " +  args[0].readCString());
        console.log("sub_352C0 Func arg2 is: " +  Memory.readPointer(args[1]).readCString());
        console.log("sub_352C0 Func arg3 is: " +  args[3].toInt32());
        console.log("sub_352C0 Func arg4 is: " +  args[4]);
    },
    onLeave: function (retval) {
        console.log("sub_352C0 Func return: " + Memory.readPointer(retval).readCString());
    }
});
```  
先看红框部分，这里明显是drift函数里面进行的两次调用，传入的参数arg2是两次base64编码的post参数值，然后return一段编码字符串。通过分析发现，返回值就是传入参数arg2的一部分，通过两次调用，返回值正好拼接成完整的arg2参数值。再看蓝框部分，这里传入的arg2似乎是一个md5值，也是调用了两次进行字符串分割，同时发现，这段md5值就是传入md5_encode函数参数尾部的Hash值，并且通过Frida打印的顺序可知，这段md5分割是在base64_encode函数之前调用的。  

![](/assets/images/2021-05-23-android-so-reverse-frist/18.png)  

返回来看看genSignature函数，发现与salt有关的a2变量还没分析过，分析a2变量的调用，可以看见a2直接传入了第20行的recover函数，该函数正好在base64_encode函数之前调用，查看recover函数，内部逻辑和drift函数差不多，内部也调用了两次sub_352C0函数，与Frida打印的日志信息吻合，然后第14行的`operator+`重载了`运算符+`，效果是将sub_352C0函数返回的字符串重新进行拼接，可以通过hook recover或者drift函数的返回值确认    

![](/assets/images/2021-05-23-android-so-reverse-frist/19.png)  

综上，我们基本分析出了整个加密逻辑。来从头到尾捋一捋:  

> 1. post请求的参数在Java层进行base64编码，然后传入native层；
> 2. native层通过dword_570A0变量获取盐值，但是变量在bss段，通过hook可知其值为`69eb2b8efd5442418e05b0f9055add1e`；  
> 3. 传入native层的base64值再次base64编码；  
> 4. salt和base64编码的字符串通过调用sub_352C0函数进行对半分割，然后重新拼接，比如原始字符串abcd变成了cdab；
> 5. 把重新拼接的salt和base64字符串再拼接在一起，然后计算其md5值，md5值即为sign签名值；  

通过分析Frida打印的日志可知，sub_352C0函数是把传入的字符串对半平分的，分析sub_352C0函数，发现变量又直接传入了sub_35278函数，该函数详情如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/20.png)  

hook一下sub_35278和第19行的sub_35204函数，结果如下，可以看见传入sub_35278的arg2（a2）是完整的salt（base64值），然后传入sub_35204的arg1参数就是已经分割的salt（base64值），从这里伪代码来看，不太好理解是如何平分字符串的。

![](/assets/images/2021-05-23-android-so-reverse-frist/21.png)  

## 0x03 SO动态调试  

sub_35278伪函数不太好理解，为了捋清楚它对字符串的分割逻辑，准备通过动态调试来分析。直接对应用进行调试，发现APP会崩溃，应该是做了反调试检测，为了使环境变得简单，我们自己写一个Demo来调用`libMapiSign.so`中的NativeMakeSignature函数，然后调试我们自己写的Demo，这样就可以绕过原应用中Java层或其他so的检测。  
开发自己的Demo应用过程中，首先要注意调用native函数的类名和包名必须跟libMapiSign.so里面的类名和包名一致，然后在app目录下新建libs目录用于存放so文件，具体如下所示  
 
![](/assets/images/2021-05-23-android-so-reverse-frist/22.png)  

build.gradle(:app)新增以下配置  

```
android {
    compileSdkVersion 30
    buildToolsVersion "30.0.2"

    defaultConfig {
......SNIP......
        //指定架构，否则打包失败
        ndk {
            abiFilters  "armeabi-v7a"
        }
    }
......SNIP......
    //设置jniLibs
    sourceSets {
        main {
            jniLibs.srcDirs = ['libs']
        }
    }
}
```  

打包编译APP，配置好IDA调试环境，在偏移0x35278处下断点  

![](/assets/images/2021-05-23-android-so-reverse-frist/23.png)  

调试运行APP发现没有在0x35278处暂停，Demo应用也没有输出任何信息。在前面静态分析的时候，可知在makeSignature函数中调用genSignature函数时，有个if判断，以伪代码中的第33行if判断为例，汇编指令如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/24.png)  

这里先调用parseSalt函数，返回值存储在R0寄存器，MOV指令将R0的值赋值给R7，然后通过CBNZ指令进行判断，语法为`CBNZ Rn, label`，其中Rn是存放操作数的寄存器，label是跳转目标。意思是如果R7的值为非零就跳转到loc_87C8。  
通过前面的静态分析可知，如果parseSalt函数解析成功则返回1，解析失败就返回0。我们编写的Demo应用，Java层传入的第一个参数是随便赋值的"test"，并且静态分析可知salt有关的变量在bss段，所以这里parseSalt函数肯定返回0，然后运行后续salt解析失败的逻辑。知道调试无法运行到断点处的原因了，那可以通过断点调试修改R7的值或者修改指令逻辑进入if语句，这里选择后者，和CBNZ指令对应的是CBZ指令，意思是如果寄存器Rn的值等于零，则跳转到label，所以我们把`CBNZ`指令修改成`CBZ`指令，那就可以进入if判断了。使用IDA插件[keypatch](https://github.com/keystone-engine/keypatch)来修改指令，如下所示  

![](/assets/images/2021-05-23-android-so-reverse-frist/25.png)  

通过`Edit->Patch Program->Apply patches to input file`保存修改后的so文件，将修改后的so文件替换到编写的Demo应用，重新编译运行APP，成功计算出了Sign值

![](/assets/images/2021-05-23-android-so-reverse-frist/26.png) 

这个sign值和正常应用计算的sign不等，原因在于我们编写的Demo在计算md5的时候，传入的字符串少了尾部的Hash值(salt)，用前面hook md5_encode函数拿到的字符串验证一下，去掉尾部的Hash值部分，得到的md5值和Deme应用打印结果的一致  

![](/assets/images/2021-05-23-android-so-reverse-frist/27.png)  

到现在，可以顺利的对sub_35278函数进行动态调试了。如果想ARM指令结合伪C代码分析，`快捷键/`可以将伪C代码显示到汇编注释中，效果如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/28.png)  

通过前面静态分析可知，recover函数里面会先调用该函数分割salt，所以需要按两次`F9`快捷键执行到断点，定位到drift函数里面的sub_35278函数，这里才开始对POST参数（*两次base64的字符串*）进行操作，如下所示，R1寄存器(*对应伪代码第二个参数a2变量*)保存传入的字符串  

![](/assets/images/2021-05-23-android-so-reverse-frist/29.png)  

单步执行，如下所示，R2相当于伪C代码中的a3变量，其值为0x46(十进制70)，正好等于传入的POST字符串长度的一半，接着`R1-0xC`位置的值等于0x8C(十进制140)，等于POST字符串的长度，接着CMP指令比较R2和R5的值

![](/assets/images/2021-05-23-android-so-reverse-frist/30.png)  

往下继续调试，可以看见传入sub_C8688204(*静态分析的sub_35204*)函数的第一个参数R0等于R1+R2，这里R1存储的是POST字符串地址，R2存储的是POST字符串一半的长度，相加获得的地址即为字符串后半段的地址  

![](/assets/images/2021-05-23-android-so-reverse-frist/31.png)  

通过调试可知一开始传入了字符串长度的一半的值，然后通过`字符串首地址+len(str)/2`获取到字符串后半段首元素地址，伪代码分析如下  

![](/assets/images/2021-05-23-android-so-reverse-frist/32.png)  

跟着sub_35278函数的a3变量回溯分析，发现drift在调用sub_352C0的时候，第三个变量进行了右移操作，这里右移一位，相当于除以2，如下所示，通过上述分析，可知这里的v4就等于传入的POST两次base64编码值的长度  

![](/assets/images/2021-05-23-android-so-reverse-frist/33.png)  

剩下就是salt盐值的问题，通过测试发现，不同的请求，salt是固定的，其值我们已通过Frida hook sub_352C0函数获得。  

## 0x04 结语  

有点老太婆的裹脚布，又长又臭的感觉，本意是想尽可能的记录出分析细节，这样对入门的朋友可能友好一点。在看文章的时候，注意对照截图中的代码，否则可能会比较乱。笔者水平有限，文章中如有理解错误的地方，还请不吝赐教。  

**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**

{%endraw%}  