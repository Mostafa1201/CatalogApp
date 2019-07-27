# Description

This is an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

# Tools

* __Framework__ : Flask
* __Language__ : Python
* __Database__ : Postgresql
* __Third Party APIS__ : Google Authentication
* __Server__ : Amazon Web Service Lightsail Instance With Ubuntu 16.04 Image
* __DNS Service__ : Xip service that offers Dns Name that refers to the instance ip address

# Configuration
- This app is hosted on Amazon Lightsail Instance that operate on Ubuntu 16.04 OS
- Python version 2 is used as well as pip version 1
- To be able to connect to the instance via ssh you need to run this command : 
```
ssh username@publicIP -i graderkey -p 2200
Example : ssh grader@52.59.96.168 -i privateKey -p 2200
```
- To be able to connect to postgresql database you need to run this command
```
psql postgresql://user:password@host/database
Example : psql postgresql://catalog:123456@localhost/catalog
```
- **IP Address** : 52.59.96.168
- **URL** : 52.59.96.168.xip.io
- **SSH port** : 2200
- **WebServer Port** : 80

- WSGI is used in this application , It is the Web Server Gateway Interface. It is a specification that describes how a web server communicates with web applications, and how web applications can be chained together to process one request.
- xip service is used in this application , this is a public service offered for free by Basecamp. For instance, the DNS name 54.84.49.254.xip.io refers to the server above.
- You can access the application via url link : [52.59.96.168.xip.io](http://52.59.96.168.xip.io) or [52.59.96.168]((http://52.59.96.168))
- The Application Has 2 ways for authentication : oauth2 and google authentication.
- CRUD operations are developed with considering user permissions and security.