/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50718
Source Host           : localhost:3306
Source Database       : shiro_demo

Target Server Type    : MYSQL
Target Server Version : 50718
File Encoding         : 65001

Date: 2020-03-22 09:51:13
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for oauth_client_details
-- ----------------------------
DROP TABLE IF EXISTS `oauth_client_details`;
CREATE TABLE `oauth_client_details` (
  `client_id` varchar(256) CHARACTER SET utf8 NOT NULL,
  `resource_ids` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `client_secret` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `scope` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `authorized_grant_types` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `authorities` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` varchar(4096) CHARACTER SET utf8 DEFAULT NULL,
  `autoapprove` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of oauth_client_details
-- ----------------------------
INSERT INTO `oauth_client_details` VALUES ('AuthorizationCode', null, '$2a$10$iHXOYDUbs8wip/6MIc3izee7SIOob.T00yOhyCB2ns/6jPAJn85CS', 'all', 'authorization_code,refresh_token', 'http://localhost:20300/login,http://localhost:20300/callback', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('AuthorizationCode2', null, '$2a$10$jatWE0Iyas4lc30N2j561u7B3JuWOa1cxX7YUSohsJjoUO9J43pKe', 'all', 'authorization_code,refresh_token', 'http://localhost:20301/login', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('AuthorizationCode3', null, '$2a$10$T.W.Ag8ax1bXWzwJJ3aOdOzzLKtz1R.LzUUs1zX7q5LRrWEXtPy26', 'all', 'authorization_code,refresh_token', 'http://localhost:20302/login', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('ClientCredentials', null, '$2a$10$lT/TGpD8OEGJ.GnWqnGQh.ZLcH7f5jcPQGI1XmEMyzFBGY0MczX2e', 'all', 'client_credentials,refresh_token', null, null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('Implicit', null, null, 'all', 'implicit', 'http://localhost:20400/login', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('Implicit2', null, null, 'all', 'implicit', 'http://localhost:20401/hi.html', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('one', null, '$2a$10$Yt3t/SbVxgJFRXDiwCz7iuw5LOJeorzeS60nQM0aOqEsqT6jNapQG', 'all', 'authorization_code,refresh_token', 'http://localhost:8081/third-party-login-by-client-two,http://localhost:8081/third-party-login-by-client-three', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('Password', null, '$2a$10$yJYXPhpQlkqgZ/Us9txo3uqaFBRLVcCX.fL1Fjwk6k03GwMoXRbn.', 'all', 'password,refresh_token', null, null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('Password2', null, '$2a$10$pkOqRu5BgaMn1DdnmA8m8eIsimq2Gjyvkpj61tlwnseEZs2z772y2', 'all', 'password,refresh_token', null, null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('subsystem', null, '$2a$10$z7mER1rNgQHUwkyoXfR5p.wA4CPoguW0gt0XWpXi/prz535A.6.MK', 'all', 'authorization_code,refresh_token', 'http://subsystem.com:8082/sso/login', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('three', null, '$2a$10$9Fc7ji0yVeJwgj5yQZwGU.nQ2kLAaqPcCa1V/oKSWq/Ph7M92VG/i', 'all', 'authorization_code,refresh_token', 'http://localhost:8083/third-party-login-by-client-one,http://localhost:8083/third-party-login-by-client-two', null, '7200', null, null, 'true');
INSERT INTO `oauth_client_details` VALUES ('two', null, '$2a$10$z7mER1rNgQHUwkyoXfR5p.wA4CPoguW0gt0XWpXi/prz535A.6.MK', 'all', 'authorization_code,refresh_token', 'http://localhost:8082/third-party-login-by-client-one,http://localhost:8082/third-party-login-by-client-three', null, '7200', null, null, 'true');
