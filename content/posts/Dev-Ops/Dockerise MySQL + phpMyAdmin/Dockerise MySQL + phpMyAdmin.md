---
author:
  name: "hexterisk"
date: 2020-07-02
linktitle: Dockerise MySQL + phpMyAdmin
type:
- post
- posts
title: Dockerise MySQL + phpMyAdmin
tags: ["docker", "mysql", "phpmyadmin", "container", "docker-compose"]
weight: 10
categories: ["Dev-Ops"]
---

A common requirement in a large number of software projects is a relational database with an easy to use management tool. Considering how often a developer needs this, setting it up everytime from scratch can be a drag. However, with the advent of containerisation, we can have a setup off the ground in a couple of minutes, whether it's a development or a production environment.

The age long discussion of MySQL versus MariaDB is something that an average developer need not bother with unless their requirement is very specific. MariaDB is a fork of MySQL and is developed separately, and therefore contains a number of incompatibilities when compared to the standard MySQL. However, the fundamental infrastructure of the database and indexing are the same:

*   Data and Table definitions are compatible.
*   Client protocols, structures, and APIs are identical.
*   MySQL connectors will work with MariaDB without modification.
*   Command-line tools and commands are mostly the same.

In fact, MariaDB developers perform a monthly merge of MariaDB's codebase with MySQL's to ensure running compatibility in future versions. Therefore there shouldn't be any trouble if the developer decides to switch the database in the middle of the development cycle.

The major difference comes in the number of storage engines supported. MariaDB(Supported [storage engines](https://mariadb.com/kb/en/library/storage-engines/)) provides support for more storage engines than MySQL([storage engines](https://dev.mysql.com/doc/refman/8.0/en/storage-engines.html)) does. One must understand that it's not a matter of which one supports more engines, it's a matter of which one supports the engine that meets the requirements.

I'll be using MySQL for the example. At any time, MySQL can be swapped out with MariaDB by simply replacing the container image.

One thing to note is that user and password can be set up for phpMyAdmin too, but you need not use them if you are not interested in changing any default configurations(mainly authentication).

## Instant Approach

The approach that leads to instant deployment of the setup is to deploy containers from the command-line itself.

This is the boiler plate config. More options like mounting volumes can be used as per requirement.

##### Deploy Database

Run `docker run --name DB_CONTAINER_NAME -e MYSQL_ROOT_PASSWORD=PASSWORD -d mysql:latest`.

*   Pass the desired name for the container to the `--name` parameter. Replace _DB\_CONTAINER\_NAME_ with the desired name.
*   Pass the password for the root user of the DB to the `-e MYSQL_ROOT_PASSWORD` parameter. Replace _PASSWORD_ with the desired password.
    *   Required by the container.
*   The `-d` parameter deploys the container in the “detached” mode, that is, in the background.
*   The `mysql:latest` parameter ensures the container is deployed with the image of latest MySQL. Can be replace with MariaDB as per requirement.
*   Username and password for any user(root included) cannot be the same, and neither of these can be equal to the root password.

The container should deploy with no issues whatsoever. Run `docker ps` to verify.

!["db"](/Dockerise_MySQL_+_phpMyAdmin/2020-07-17-200632-screenshot.png)
_Sample output for database container._

Following the screenshot, I deployed a MySQL container named _test\_sql\_container_ with the password _rootpassword_.

##### Deploy phpMyAdmin

Run `docker run --name CONTAINER_NAME -d --link DB_CONTAINER_NAME:db -p PORT:80 phpmyadmin/phpmyadmin`.

*   Pass the desired name for the container to the `--name` parameter. Replace _CONTAINER\_NAME_ with the desired name.
*   Pass the name of the container deployed for DB previously to the `--link` parameter. Replace _DB\_CONTAINER\_NAME_ like before.
*   Pass the port to bind the container to the `-p` parameter. Replace _PORT_ with the desired port number.
*   The `phpmyadmin/phpmyadmin` is the docker image as listed on docker hub.

The container should deploy with no issues whatsoever. Run `docker ps` to verify.

!["docker-up"](/Dockerise_MySQL_+_phpMyAdmin/2020-07-17-200743-screenshot.png)
_Sample output for database and management tool containers._

Following the screenshot, I deployed a phpMyAdmin container named _test\_myadmin\_container_ linked to a database container named _test\_sql\_container_ attached to port _8081_.

Login to phpMyAdmin page on `localhost:PORT` with `root:PASSWORD`(username: root and password: PASSWORD), where _PORT_ is the port phpMyAdmin is bound to in the second stage, and the _PASSWORD_ is the root password set in the first stage.

According to the commands I entered (following the screenshots), I can access the phpMyAdmin dashboard on `localhost:8081` and I can login using the credentials `root:rootpassword`.

DISCLAIMER: These containers are ephemeral and will not save any state since no volumes have been mounted. Any changes made will be lost when the container are closed. Checkout the documentation to see [how to mount volumes](https://docs.docker.com/storage/volumes/) if you're not familiar with it.

## Composed Approach

This approach involves writing a docker-compose file. The content will be as follows.

```yaml
version: "3.7"
services:

  db-server:
    image: mysql:latest
    container_name: test_sql_container
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: secret
    ports:
      - "3306:3306"
    
  phpmyadmin:
    image: phpmyadmin/phpmyadmin
    container_name: test_myadmin_container
    restart: always
    environment:
      PMA_HOST: db-server
    links:
      - db-server
    ports:
      - "8081:80"
```

Apart from the common parameters such as the `image` and `container_name`, following things should be noticed.

For the database container:

*   `MYSQL_ROOT_PASSWORD` parameter can not be given the value “root” for password.
*   Username and password for any user(root included) cannot be the same, and neither of these can be equal to the root password.

For the management panel container:

*   An environment variable for `PMA_HOST` has to be set to the name of the database service(_db-server_ in the file). It defines the address/host name of the database server.
*   The database service needs to be explicitly linked to the management panel container using the parameter `links`.

Run `docker-compose up -d` to deploy the containers based on the docker-compose file.

!["containers"](/Dockerise_MySQL_+_phpMyAdmin/2020-07-17-213248-screenshot.png)
_Sample output._

The containers have been deployed as follows. Modifications to the docker-compose file can be made as per requirement, use the sample file above to maintain consistency so that the right parameters receive the right