DROP TABLE IF EXISTS user;
CREATE  TABLE user (
	id int(11) not null primary key auto_increment,
  user_name VARCHAR(100) NOT NULL ,
  password VARCHAR(100) NOT NULL ,
  is_active boolean NOT NULL,
  roles VARCHAR(100) NOT NULL 
 );
 
 
insert  into `user`(`id`,`is_active`,`password`,`roles`,`user_name`)
values (1,1,'user@123','ROLE_USER','user'),
(2,1,'admin@123','ROLE_ADMIN','admin');