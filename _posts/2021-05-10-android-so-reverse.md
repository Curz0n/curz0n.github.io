---
layout: post
title: Android so层逆向分析入门  
date: 2021-5-10 20:49:22 +0800 #2020-9-25 20:04:15 +0800
categories: 移动安全
tag: Android Sec
---

* content
{:toc}

{%raw%}  

## 0x00 前言  

在看雪论坛看见一大佬分享的so层逆向分析帖子，目标apk核心逻辑被抽到native层动态注册，并对字符串和核心函数逻辑进行了加密。原帖地址[请戳这里](https://bbs.pediy.com/thread-261203.htm)，笔者也对app分析了一遍，分析到动态注册函数的具体实现时，由于水平不足遇到了障碍，最后发现另外一大佬也分享了其分析过程，且相对比较详细，原帖[请戳这里](https://bbs.pediy.com/thread-260547.htm)，笔者感觉比较经典，适合对so层逆向入门的整体把控，遂记录一下自己的分析流程，样本请戳原帖文末附件下载。  

## 0x01 逆向分析  

### 1. Java层分析  

把apk拖进jeb，发现使用了某数字进行加固，对app进行脱壳，分析可知其关键方法test被注册成了native函数。  

![](/assets/images/2021-05-10-android-so-reverse/1.png)  

### 2. so层分析  

#### 2.1 JNI静态注册与动态注册  

JNI注册方法分为静态注册和动态注册，静态注册的方法可以在IDA的函数窗口或者导出表中直接找到，比较简单。动态注册的方法需要分析`JNI_OnLoad`函数，把libnative-lib.so拖进ida神器，分析Exports导出表，可知上图中的stringFromJNI方法是静态注册，而test方法是动态注册。   

![](/assets/images/2021-05-10-android-so-reverse/2.png)  
 
在分析JNI_OnLoad函数之前，先简单回顾下JNI方法动态注册流程:  

```c++
//第一步，实现JNI_OnLoad方法
JNIEXPORT jint JNI_OnLoad(JavaVM* jvm, void* reserved){
    //第二步，获取JNIEnv
    JNIEnv* env = NULL;
    if(jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK){
        return JNI_FALSE;
    }
    //第三步，获取注册方法所在Java类的引用
    jclass clazz = env->FindClass("com/curz0n/MainActivity");
    if (!clazz){
        return JNI_FALSE;
    }
    //第四步，动态注册native方法
    if(env->RegisterNatives(clazz, gMethods, sizeof(gMethods)/sizeof(gMethods[0]))){
        return JNI_FALSE;
    }
    return JNI_VERSION_1_6;
}
```  
其中第四步gMethods变量是JNINativeMethod结构体，用于映射Java方法与C/C++函数的关系，其定义如下:  

```c++
typedef struct {
    const char* name; //动态注册的Java方法名
    const char* signature; //描述方法参数和返回值
    void*       fnPtr; //指向实现Java方法的C/C++函数指针
} JNINativeMethod;
```  

#### 2.2 JNI_OnLoad分析  

定位到JNI_OnLoad方法，伪代码如下:  

![](/assets/images/2021-05-10-android-so-reverse/3.png)  

我们知道JNI_OnLoad函数的第一个参数是`JavaVM`指针类型，这里IDA工具不能自动识别，所以需要手动修复一下，选中int，右键选择Set lvar tyep(快捷键Y)重新设置变量类型:  

![](/assets/images/2021-05-10-android-so-reverse/4.png)  

跟踪a1变量进入sub_9230函数    

![](/assets/images/2021-05-10-android-so-reverse/5.png)  

ida同样没有把a1变量类型正确识别，所以需要将第一个参数类型修改成JavaVM指针，伪代码中的结构体也自动被识别出来了  

![](/assets/images/2021-05-10-android-so-reverse/6.png)  

这里看见伪代码中的GetEnv函数可读性依然不强，还需要修复，选中函数名，右键选择Force call type，修复后效果如下:  

![](/assets/images/2021-05-10-android-so-reverse/7.png)  

从JNI动态注册流程中可知，jvm->GetEnv的第一个参数是JNIEnv指针，对应这里伪代码中的第二个变量a2，回到JNI_OnLoad函数，可知v3变量就是JNIEnv指针类型:  

![](/assets/images/2021-05-10-android-so-reverse/8.png)  

跟踪v3进入到sub_9264函数，对函数进行修复，可知sub_9264函数其实就是env->FindClass函数

![](/assets/images/2021-05-10-android-so-reverse/9.png)  

继续分析JNI_OnLoad中的sub_928E函数，可知sub_928E函数是env->RegisterNatives函数  

![](/assets/images/2021-05-10-android-so-reverse/10.png)  

通过分析可知，JNI_OnLoad函数中的v4指针指向的就是JNINativeMethod结构体  

![](/assets/images/2021-05-10-android-so-reverse/11.png)  

这里v4等于&unk_1C066，跟进unk_1C066变量，发现其值被加密  

![](/assets/images/2021-05-10-android-so-reverse/12.png)  

#### 2.3 .init段分析  

在链接so共享目标文件的时候，如果so中存在.init和.init_array段，则会先执行.init和.init_array段的函数，然后再执行JNI_OnLoad函数。通过静态分析可知，JNI_OnLoad函数中的v4指针指向的地址上的变量值是加密状态，在实际运行的过程中，v4指针指向的地址上的值应该是解密状态，所以解密的操作应该在JNI_OnLoad函数运行之前，.init或者.init_array段上的函数。  
查看Segments视图（快捷键Ctrl+S），该目标文件只存在.init_array段:  

![](/assets/images/2021-05-10-android-so-reverse/13.png)  

定位到.init_array段，发现这里定义了一个解密函数  

![](/assets/images/2021-05-10-android-so-reverse/14.png)  

分析伪代码，其实就是一个异或算法  

![](/assets/images/2021-05-10-android-so-reverse/15.png)  

这里反汇编后，变量名被IDA工具自动更新，返回IDA View视图，unk_1C066变量名被修复成了byte_1C066  

![](/assets/images/2021-05-10-android-so-reverse/16.png)  

结合解密算法，其值解密结果如下，正好对应Java中的test方法  

![](/assets/images/2021-05-10-android-so-reverse/17.png)  

JNINativeMethod结构体的第二个成员signature描述了方法的参数和返回值，对应于byte_1C070吗？解密发现其值正好是test方法的参数和返回类型  

![](/assets/images/2021-05-10-android-so-reverse/18.png)  

JNINativeMethod结构体的第三个成员指向实现Java方法的C/C++函数地址，so文件的.data段一般是保存已经初始化的全局静态变量和局部变量，动态注册函数的信息一般存放在`.data.rel.ro.local`段。在IDA View视图选中byte_1C066或者byte_1C070变量，交叉引用（快捷键X）跳转到.data.rel.ro段

![](/assets/images/2021-05-10-android-so-reverse/19.png)  

off_1A5C8的值为byte_1C066(动态注册的方法名test)，off_1A5CC的值为byte_1C070，那off_1A5D0的值ooxx一定就是test方法的注册地址，正好对应于JNINativeMethod结构体的三个字段。  

![](/assets/images/2021-05-10-android-so-reverse/20.png)  

#### 2.4 函数逻辑分析  

跳转到ooxx函数，伪代码如下所示，一个JUMPOUT函数  

![](/assets/images/2021-05-10-android-so-reverse/21.png)  

IDA反汇编出现JUMPOUT的原因是函数边界识别错误或者某些原因导致代码不在一个连续的区域，参考资料[戳这里](https://bbs.pediy.com/thread-256912.htm)。继续跟进sub_8930()函数，伪代码如下  

![](/assets/images/2021-05-10-android-so-reverse/22.png)  

先看第17行的v11变量，选中数字右键选择Char(快捷键R)，将数字转换成字符串，其值为`xxoo`，这里因为字节序的原因，正确值应该为`ooxx`。接着看第18行的sub_8A88()函数，详情如下:  

![](/assets/images/2021-05-10-android-so-reverse/23.png)  

对第15行第unk_1C0AD变量解密，其值如下  

![](/assets/images/2021-05-10-android-so-reverse/24.png)  

分析代码可知，这里就是在获取libnative-lib.so文件映射在内存中的基地址  

![](/assets/images/2021-05-10-android-so-reverse/25.png)  

代码具体分析如下  

![](/assets/images/2021-05-10-android-so-reverse/26.png)  

#### 2.5 定位函数偏移  

回到sub_8930()函数，继续分析第19行的sub_8B90()函数，代码及分析结果如下，这里把libnative-lib.so基地址和字符串ooxx作为参数传入，第三个参数用于保存返回结果，为了方便分析，可以把IDA自动命名的变量名重命名一下，选中需要重命名的变量名，右键选择Rename lvar(快捷键N)。为了方便比对IDA翻译的伪代码，笔者只对传入的参数变量进行重命名，其他以注释的方式标注    

![](/assets/images/2021-05-10-android-so-reverse/27.png)  

上图对所有代码进行了详细分析，并以注释的方式还原代码，最后结果就是把加密函数(ooxx)的地址和大小保存在a3数组中。为了进一步的理解ELF文件，这里使用010 Editor打开so文件对照代码手动解析一下。  

##### 2.5.1 ELF解析  

**注：该小结只是以可视化方式展现代码逻辑，核心内容与上图注释重叠，对ELF文件格式很了解的同学可以直接跳过该小结。**  

先分析第一句代码（第28行），首先基地址加28（0x1C）获取程序头表偏移值52(0x34)，  

![](/assets/images/2021-05-10-android-so-reverse/28.png)  

接着0x34再加基地址（本地打开so，基地址就是0x00），拿到程序头表  

![](/assets/images/2021-05-10-android-so-reverse/29.png)  

第29行代码，for语句里面的baseAddr + 44(0x2C)，获取程序头表数量，相当于程序执行视图中的Segment个数  

![](/assets/images/2021-05-10-android-so-reverse/30.png)  

程序头表是一个Elf32_Phdr类型的结构数组，定义如下所示  

```c
typedef struct
{
  Elf32_Word    p_type;         /* Segment type */
  Elf32_Off     p_offset;       /* Segment file offset */
  Elf32_Addr    p_vaddr;        /* Segment virtual address */
  Elf32_Addr    p_paddr;        /* Segment physical address */
  Elf32_Word    p_filesz;       /* Segment size in file */
  Elf32_Word    p_memsz;        /* Segment size in memory */
  Elf32_Word    p_flags;        /* Segment flags */
  Elf32_Word    p_align;        /* Segment alignment */
} Elf32_Phdr;
```  

for循环遍历程序头表，如果Elf32_Phdr.p_type为PT_DYNAMIC(2)，则结束循环  

![](/assets/images/2021-05-10-android-so-reverse/31.png)  

其实就是找到.dynamic段，该段主要与动态链接的整个过程有关，保存的是与动态链接相关信息，主要用于寻找与动态链接相关的其他节( .dynsym .dynstr .hash等节)。如下所示  

![](/assets/images/2021-05-10-android-so-reverse/32.png)  

第43到66行的for循环里面，拿到了.dynsym、.dynstr、.hash等section的地址，.dynsym区节包含了动态链接符号表，符号表定义如下  

```c
typedef struct
{ 
    Elf32_Word    st_name;   //函数符号在字符串表中的索引  .dynstr_offset + st_name就是函数符号的具体位置
    Elf32_Addr    st_value;  //函数代码实现的位置地址
    Elf32_Word    st_size;   //函数代码的长度
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half    st_shndx;
} Elf32_Sym; 
``` 

第73行获取到hash表，hash表结构组织如下所示  

```  
-------------------------------  
            nbucket
-------------------------------  
            nchain  
-------------------------------  
            bucket[0]
-------------------------------  
            ...
-------------------------------  
            bucket[nbucket-1]
-------------------------------  
            chain[0]
-------------------------------  
            ...
-------------------------------  
            chain[nchain-1]
-------------------------------  
```  

每个元素由Elf32_Word（大小为4个字节）对象组成，我们使用链接视图看看hash表，这里nbucket=0x107，nchain=0x1B1，一共有(0x107 + 0x1B1 + 2) * 4 = 2792字节大小，如下所示  

![](/assets/images/2021-05-10-android-so-reverse/33.png)  

第74行使用hash函数（sub_92D6）计算符号的hash值，ELF的哈希函数是公开的，编译运行得到其hash值为0x766f8  

```c  
int main(void){
    const char *_name = "ooxx";
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;
    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    printf("%x\n",h); //0x766f8
    return h;
}
```  

第76到85行就是根据hash值与nbucket取模作为bucket链的索引，bucket[hash % nbucket]的值作为.dynsym的索引获得动态链接符号表(Elf32_Sym)，从符号表的st_name找到.dynstr中对应的字符串与函数名相比较，若不等，则根据bucket[hash % nbucket]的值X作为chain链的索引，chain[X]的值重新获取一个动态链接符号表，拿到字符串索引后获取.dynstr中对应的字符串与函数名相比较，若再不等，继续根据chain[X]的值Y作为chain链的索引，chain[Y]的值重新获取一个动态链接符号表，直到找到或者chain终止为止。代码实现如下  

```c
for(i = bucket[funHash % nbucket]; i != 0; i = chain[i]){  
  if(strcmp(dynstr + (dynsym + i)->st_name, funcName) == 0){  
    flag = 0;  
    break;  
  }  
} 
```  

看上去还是比较绕，我们在010 Editor里面手动计算一下，函数Hash值在74行代码中已经计算得到0x766F8，nbucket=0x107，mod为hash % nbucket = 140，因为hash表的前两个元素是nbucket和nchain，每个元素是Elf32_Word类型，大小为4，所以bucket[hash % nbucket]是第(140 + 2) * 4 = 568号字节，其值为0x19B  

![](/assets/images/2021-05-10-android-so-reverse/34.png)  

0x19B做为.dynsym动态链接符号表(Elf32_Sym)的索引，Elf32_Sym对象大小为16字节，所以在符号表的位置为0x19B * 16 = 6576号字节，st_name是Elf32_Sym对象的第一个元素，所以其值为0x1617  

![](/assets/images/2021-05-10-android-so-reverse/35.png)  

.dynstr字符串表的offset等于0x1D00  

![](/assets/images/2021-05-10-android-so-reverse/36.png)  

st_name为索引的字符串位置则等于0x1D00 + 0x1617 = 0x3317，对应字符串"_ZTIPn"，与ooxx不等。所以需要计算chain[0x19B]的值。先计算chain的起始位置为(nbucket + 2) * 4，nbucket = 0x107，所以chain的起始位置为1060号字节，0x19B十进制为411，那chain链的411索引对应的字节应该是1060 + 411 * 4 = 2704号字节，值为0x5D  

![](/assets/images/2021-05-10-android-so-reverse/37.png)  

对应.dynsym动态链接符号表的位置为0x5D * 16 = 1488号字节，st_name = 0x214  

![](/assets/images/2021-05-10-android-so-reverse/38.png)  

对应的字符串地址为0x1D00 + 0x214 = 0x1F14，字符串值为"ooxx"，是我们需要查找的符号。结合上图，则可知Elf32_Sym对象的st_value = 0x8DC5，st_size = 0x248  

![](/assets/images/2021-05-10-android-so-reverse/39.png)  

手动解析非常痛苦，不过对ELF文件格式的理解非常有帮助，用readelf命令直接查看一下，其结果与我们手动解析的结果一致  

![](/assets/images/2021-05-10-android-so-reverse/40.png)  

#### 2.6 函数解密  

上述sub_8B90函数最后返回0，所以在sub_8930函数的第19行if判断结果为false，然后开始执行第23行的else逻辑。具体分析如下  

![](/assets/images/2021-05-10-android-so-reverse/41.png)  

第26行的v10变量，伪代码中没有对该变量进行赋值，双击v9和v10发现他们在堆栈是连续的，其实对应于sub_8B90函数最后的st_value和st_size赋值给v9指针，所以v10变量就是st_size  

![](/assets/images/2021-05-10-android-so-reverse/42.png)  

第36行，这里的`i`表示加(解)密代码的起始地址，通过遍历地址然后解引与byte_1C180数组中的值进行异或运算得到明文，这里的byte_1C180数组就相当于是解密密钥。查看byte_1C180，发现其定义在`.bss`段  

![](/assets/images/2021-05-10-android-so-reverse/43.png)  

bss段通常是用来存放程序中未初始化的全局变量的一块内存区域，静态分析的情况下，无法查看其值，比较方便的方法是程序运行起来后，直接将对应内存中的数据dump下来，那就需要知道byte_1C180数组在内存中的起始地址和大小。  
起始地址比较容易计算，等于`libnative-lib.so在内存中的基地址 + 0x1C180`。通过分析第35行的for循环，可知数组的大小就等于`v4-v5`，即(v8 + v9 + v10 - 61) - (v8 + v9 + 59) = v10 - 61 - 59 = st_size - 61 - 59 = 0x248 - 61 - 59 = 464。根据上述信息，使用frida脚本dump内存即可得到byte_1C180数组内容，这里我们直接使用objection，先用命令`memory list modules`查看libnative-lib.so在内存中的基地址，然后dump出内存数据:    

![](/assets/images/2021-05-10-android-so-reverse/44.png)  

密钥内容如下  

![](/assets/images/2021-05-10-android-so-reverse/45.png)  

结合伪代码解密逻辑，patch脚本如下  

```python
key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
       0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
       0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
       0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
       0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
       0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
       0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
       0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
       0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
       0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
       0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
       0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
       0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
       0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
       0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
       0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
       0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
       0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
       0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
       0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
       0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
       0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
       0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF]
def patchFunc(addr,size,key):
    for i in range(size):
        # 从addr处读取1个字节的内容
        byte = get_bytes(addr + i, 1)
        # 异或运算解密
        decodeBuf = ord(byte) ^ key[i]
        print("i: %d, addr: %s, bytes_hex: %s, decode_bytes_hex: %s" % (i,hex(addr + i),hex(ord(byte)),hex(decodeBuf)))
        # 将addr地址处patch成decodeBuf的内容
        patch_byte(addr + i, decodeBuf)
patchFunc(0x8e00,464,key)
```  
##### 2.6.1 PATCH  

IDA选择File-Script command，language选择python，运行脚本如下  

![](/assets/images/2021-05-10-android-so-reverse/46.png)  

查看ooxx函数，发现JUMPOUT函数消失了  

![](/assets/images/2021-05-10-android-so-reverse/47.png)  

分析汇编指令，发现函数结尾没有正确识别，且指令没有解析，如下所示  

![](/assets/images/2021-05-10-android-so-reverse/48.png)  

定位到0x8E4C结尾处，按`快捷键E`，设置ooxx函数结尾，然后选中DCD定义的数据，按`快捷键C`，将数据转换成ARM指令  

![](/assets/images/2021-05-10-android-so-reverse/49.png)  

重新查看ooxx函数，解密后的ooxx函数内容如下  

![](/assets/images/2021-05-10-android-so-reverse/50.png)  

## 0x02 结语  

这篇文章拖拖拉拉写了很久，中间还搁置了几个月没动笔，期间发现52上面也有一大牛对这个app进行了分析，文章地址戳[这里](https://www.52pojie.cn/thread-1396626-1-1.html)，最近得闲决定还是把它写完，笔者水平有限，文章中如有理解错误的地方，还请不吝赐教。  

**References:**  
[安卓加固之so文件加固](https://www.cnblogs.com/aliflycoris/p/5880195.html)  
[ELF 文件格式分析 - 北京大学操作系统实验室
](http://www.doc88.com/p-0873984771825.html)  
[记一次so文件动态解密](https://bbs.pediy.com/thread-260547.htm)  

**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**

{%endraw%}  