DROP DATABASE IF EXISTS MOVIEAPP;
CREATE DATABASE MOVIEAPP; 
USE MOVIEAPP;

DROP TABLE IF EXISTS REGISTERED_USER;
CREATE TABLE REGISTERED_USER (
	id 						varchar(255) DEFAULT(uuid()) not null,
	first_name 					varchar(255),
	last_name 					varchar(255),
	email_address 					varchar(255) 	not null unique,
	password 					varchar(255),
	address 					varchar(255) 	not null,
	credit_card 					varchar(255) 	not null,
	-- debit_credentials				varchar(255) not null,
	annual_fee_expiry_date 				DateTime,
	primary key (id)
);

-- user passwords have been hashed. All users have password '1234'
INSERT INTO REGISTERED_USER (id, first_name, last_name, email_address, password ,address, credit_card, annual_fee_expiry_date)
VALUES
('U_0001','Bob', 'The_Guy','btg@ucalgary.ca', '$2b$10$wfKMECuJ2EsloQPATbwsOO/rTU/eI3zUfwD8UwNui7nX4dSnk7xAa', '123 Streetname NW, Calgary, AB','1234 9876 0192 8374', '2023-11-26 09:00:00'),
('U_0002','Real', 'Person','rperson@ucalgary.ca', '$2b$10$wfKMECuJ2EsloQPATbwsOO/rTU/eI3zUfwD8UwNui7nX4dSnk7xAa','8900 RealPlace NE, Calgary, AB','1046 2894 9101 3949', '2023-11-26 09:00:00'),
('U_0003','Why', 'OhWhyat', 'wow@ucalgary.ca', '$2b$10$wfKMECuJ2EsloQPATbwsOO/rTU/eI3zUfwD8UwNui7nX4dSnk7xAa', '9031 RiverHouse SE, Calgary, AB','9374 0129 0932 5674', '2023-11-26 09:00:00'),
('U_0004', 'Wendy', 'Thomas', 'wthomas@ucalgary.ca', '$2b$10$wfKMECuJ2EsloQPATbwsOO/rTU/eI3zUfwD8UwNui7nX4dSnk7xAa', '257 East Broad Street SW, Calgary, AB', '1113 1919 9191 1234','2023-11-26 09:00:00');


DROP TABLE IF EXISTS MOVIE;
CREATE TABLE MOVIE (
	movie_id 					varchar(255) DEFAULT(uuid()) not null,
	movie_name 					varchar(255) 	not null,
	isPresale 					boolean not null,
	primary key (movie_id)
);

INSERT INTO MOVIE (movie_id, movie_name, isPresale)
VALUES
('M_001','Citizen Kane', false),
('M_002','Titanic', false),
('M_003','Demon Slayer', false),
('M_004','The Good, The Bad, And The Ugly', false),
('M_005','Citizen Kane 2', true);

DROP TABLE IF EXISTS THEATRE;
CREATE TABLE THEATRE(
	theatre_id 					varchar(255) DEFAULT(uuid()) not null,
	theatre_name 					varchar(255) 	not null,
	primary key (theatre_id)
);

INSERT INTO THEATRE (theatre_id, theatre_name)
VALUES
('T_001','MovieTown NE'),
('T_002','Cineplex SW'),
('T_003','Landmark NE');

DROP TABLE IF EXISTS SHOWING;
CREATE TABLE SHOWING(
	showing_id 					varchar(255) DEFAULT(uuid()) not null,
	theatre_id 					varchar(255) 	not null,
	movie_id 					varchar(255) 	not null,
	show_time 					DateTime,
	primary key (showing_id),
	foreign key (theatre_id) references THEATRE(theatre_id),
	foreign key (movie_id) references MOVIE(movie_id)
);

INSERT INTO SHOWING (showing_id, theatre_id, movie_id, show_time)
VALUES
('ST_001','T_001','M_001','2022-11-26 09:00:00'),
('ST_002','T_002','M_002','2022-11-26 11:00:00'),
('ST_003','T_003','M_002','2022-11-26 13:00:00'),
('ST_004','T_003','M_003','2022-11-26 09:00:00'),
('ST_005','T_002','M_004','2022-12-10 09:00:00'),
('ST_006','T_001','M_005','2022-12-11 09:00:00');

DROP TABLE IF EXISTS SEATS;
CREATE TABLE SEATS(
	seat_id 				varchar(255) DEFAULT(uuid()) not null,
	seat_label  				varchar(255) 	not null,
	showing_id 				varchar(255) 	not null,
	booked 					boolean,	
	cost 					decimal(13,2) DEFAULT(10)not null,
	primary key (seat_id),
	foreign key (showing_id) references SHOWING(showing_id)
    
);

INSERT INTO SEATS (seat_id, seat_label, showing_id, booked)
VALUES
-- seat id follows pattern: S_MonthDayYear_Time_Theatre_Movie_Seat#,,,,
('S_112622_9_001_001_01','S_A01','ST_001', true), 
('S_112622_9_001_001_02','S_A02','ST_001', false), 
('S_112622_9_001_001_03','S_A03','ST_001', false), 
('S_112622_9_001_001_04','S_A04','ST_001', false), 
('S_112622_9_001_001_05','S_A05','ST_001', false), 
('S_112622_9_001_001_06','S_A06','ST_001', true), 
('S_112622_9_001_001_07','S_A07','ST_001', true), 
('S_112622_9_001_001_08','S_A08','ST_001', false), 
('S_112622_9_001_001_09','S_A09','ST_001', false), 
('S_112622_9_001_001_10','S_A10','ST_001', false), 
('S_112622_9_001_001_11','S_B01','ST_001', false), 
('S_112622_9_001_001_12','S_B02','ST_001', false), 
('S_112622_9_001_001_13','S_B03','ST_001', false), 
('S_112622_9_001_001_14','S_B04','ST_001', false), 
('S_112622_9_001_001_15','S_C01','ST_001', false), 
('S_112622_9_001_001_16','S_C02','ST_001', false), 
('S_112622_9_001_001_17','S_C03','ST_001', false), 
('S_112622_9_001_001_18','S_C04','ST_001', false), 
('S_112622_9_001_001_19','S_D01','ST_001', false), 
('S_112622_9_001_001_20','S_D02','ST_001', true), 
('S_112622_9_001_001_21','S_D03','ST_001', false), 
('S_112622_9_001_001_22','S_D04','ST_001', false), 
('S_112622_9_001_001_23','S_D05','ST_001', false), 
('S_112622_9_001_001_24','S_D06','ST_001', false), 
('S_112622_9_001_001_25','S_D07','ST_001', false), 
('S_112622_9_001_001_26','S_D08','ST_001', false), 
('S_112622_9_001_001_27','S_D09','ST_001', false), 
('S_112622_9_001_001_28','S_D10','ST_001', false), 
-- Second showing,,,, 
('S_112622_11_002_002_1','S_A01','ST_002', false), 
('S_112622_11_002_002_2','S_A02','ST_002', false), 
('S_112622_11_002_002_3','S_A03','ST_002', false), 
('S_112622_11_002_002_4','S_A04','ST_002', false), 
('S_112622_11_002_002_5','S_A05','ST_002', true), 
('S_112622_11_002_002_6','S_A06','ST_002', false), 
('S_112622_11_002_002_7','S_A07','ST_002', false), 
('S_112622_11_002_002_8','S_A08','ST_002', false), 
('S_112622_11_002_002_9','S_A09','ST_002', false), 
('S_112622_11_002_002_10','S_A10','ST_002', false), 
('S_112622_11_002_002_11','S_B01','ST_002', true), 
('S_112622_11_002_002_12','S_B02','ST_002', true), 
('S_112622_11_002_002_13','S_B03','ST_002', true), 
('S_112622_11_002_002_14','S_B04','ST_002', true), 
('S_112622_11_002_002_15','S_C01','ST_002', false), 
('S_112622_11_002_002_16','S_C02','ST_002', false), 
('S_112622_11_002_002_17','S_C03','ST_002', false), 
('S_112622_11_002_002_18','S_C04','ST_002', false), 
('S_112622_11_002_002_19','S_D01','ST_002', false), 
('S_112622_11_002_002_20','S_D02','ST_002', false), 
('S_112622_11_002_002_21','S_D03','ST_002', false), 
('S_112622_11_002_002_22','S_D04','ST_002', false), 
('S_112622_11_002_002_23','S_D05','ST_002', false), 
('S_112622_11_002_002_24','S_D06','ST_002', false), 
('S_112622_11_002_002_25','S_D07','ST_002', false), 
('S_112622_11_002_002_26','S_D08','ST_002', false), 
('S_112622_11_002_002_27','S_D09','ST_002', false), 
('S_112622_11_002_002_28','S_D10','ST_002', false), 
-- Third Showing,,,, 
('S_112622_9_003_003_1','S_A01','ST_003', false), 
('S_112622_9_003_003_2','S_A02','ST_003', false), 
('S_112622_9_003_003_3','S_A03','ST_003', false), 
('S_112622_9_003_003_4','S_A04','ST_003', true), 
('S_112622_9_003_003_5','S_A05','ST_003', false), 
('S_112622_9_003_003_6','S_A06','ST_003', false), 
('S_112622_9_003_003_7','S_A07','ST_003', false), 
('S_112622_9_003_003_8','S_A08','ST_003', false), 
('S_112622_9_003_003_9','S_A09','ST_003', false), 
('S_112622_9_003_003_10','S_A10','ST_003', false), 
('S_112622_9_003_003_11','S_B01','ST_003', false), 
('S_112622_9_003_003_12','S_B02','ST_003', false), 
('S_112622_9_003_003_13','S_B03','ST_003', false), 
('S_112622_9_003_003_14','S_B04','ST_003', false), 
('S_112622_9_003_003_15','S_C01','ST_003', false), 
('S_112622_9_003_003_16','S_C02','ST_003', false), 
('S_112622_9_003_003_17','S_C03','ST_003', false), 
('S_112622_9_003_003_18','S_C04','ST_003', false), 
('S_112622_9_003_003_19','S_D01','ST_003', false), 
('S_112622_9_003_003_20','S_D02','ST_003', false), 
('S_112622_9_003_003_21','S_D03','ST_003', false), 
('S_112622_9_003_003_22','S_D04','ST_003', false), 
('S_112622_9_003_003_23','S_D05','ST_003', false), 
('S_112622_9_003_003_24','S_D06','ST_003', false), 
('S_112622_9_003_003_25','S_D07','ST_003', false), 
('S_112622_9_003_003_26','S_D08','ST_003', false), 
('S_112622_9_003_003_27','S_D09','ST_003', true), 
('S_112622_9_003_003_28','S_D10','ST_003', true), 
-- Fourth Showing,,,, 
('S_112622_13_003_002_1','S_A01','ST_004', false), 
('S_112622_13_003_002_2','S_A02','ST_004', false), 
('S_112622_13_003_002_3','S_A03','ST_004', false), 
('S_112622_13_003_002_4','S_A04','ST_004', false), 
('S_112622_13_003_002_5','S_A05','ST_004', false), 
('S_112622_13_003_002_6','S_A06','ST_004', false), 
('S_112622_13_003_002_7','S_A07','ST_004', true), 
('S_112622_13_003_002_8','S_A08','ST_004', false), 
('S_112622_13_003_002_9','S_A09','ST_004', false), 
('S_112622_13_003_002_10','S_A10','ST_004', false), 
('S_112622_13_003_002_11','S_B01','ST_004', false), 
('S_112622_13_003_002_12','S_B02','ST_004', false), 
('S_112622_13_003_002_13','S_B03','ST_004', false), 
('S_112622_13_003_002_14','S_B04','ST_004', false), 
('S_112622_13_003_002_15','S_C01','ST_004', false), 
('S_112622_13_003_002_16','S_C02','ST_004', false), 
('S_112622_13_003_002_17','S_C03','ST_004', false), 
('S_112622_13_003_002_18','S_C04','ST_004', false), 
('S_112622_13_003_002_19','S_D01','ST_004', false), 
('S_112622_13_003_002_20','S_D02','ST_004', false), 
('S_112622_13_003_002_21','S_D03','ST_004', false), 
('S_112622_13_003_002_22','S_D04','ST_004', false), 
('S_112622_13_003_002_23','S_D05','ST_004', false), 
('S_112622_13_003_002_24','S_D06','ST_004', false), 
('S_112622_13_003_002_25','S_D07','ST_004', false), 
('S_112622_13_003_002_26','S_D08','ST_004', false), 
('S_112622_13_003_002_27','S_D09','ST_004', true), 
('S_112622_13_003_002_28','S_D10','ST_004', true), 
-- Fifth Showing,,,, 
('S_121022_9_002_004_1','S_A01','ST_005', false), 
('S_121022_9_002_004_2','S_A02','ST_005', false), 
('S_121022_9_002_004_3','S_A03','ST_005', false), 
('S_121022_9_002_004_4','S_A04','ST_005', false), 
('S_121022_9_002_004_5','S_A05','ST_005', false), 
('S_121022_9_002_004_6','S_A06','ST_005', false), 
('S_121022_9_002_004_7','S_A07','ST_005', false), 
('S_121022_9_002_004_8','S_A08','ST_005', false), 
('S_121022_9_002_004_9','S_A09','ST_005', false), 
('S_121022_9_002_004_10','S_A10','ST_005', false), 
('S_121022_9_002_004_11','S_B01','ST_005', false), 
('S_121022_9_002_004_12','S_B02','ST_005', false), 
('S_121022_9_002_004_13','S_B03','ST_005', false), 
('S_121022_9_002_004_14','S_B04','ST_005', false), 
('S_121022_9_002_004_15','S_C01','ST_005', true), 
('S_121022_9_002_004_16','S_C02','ST_005', true), 
('S_121022_9_002_004_17','S_C03','ST_005', false), 
('S_121022_9_002_004_18','S_C04','ST_005', false), 
('S_121022_9_002_004_19','S_D01','ST_005', false), 
('S_121022_9_002_004_20','S_D02','ST_005', false), 
('S_121022_9_002_004_21','S_D03','ST_005', false), 
('S_121022_9_002_004_22','S_D04','ST_005', false), 
('S_121022_9_002_004_23','S_D05','ST_005', false), 
('S_121022_9_002_004_24','S_D06','ST_005', false), 
('S_121022_9_002_004_25','S_D07','ST_005', false), 
('S_121022_9_002_004_26','S_D08','ST_005', true), 
('S_121022_9_002_004_27','S_D09','ST_005', false), 
('S_121022_9_002_004_28','S_D10','ST_005', false),
-- Sixth Showing,,,,
('S_112622_9_001_002_01','S_A01','ST_006', true), 
('S_112622_9_001_002_02','S_A02','ST_006', false), 
('S_112622_9_001_002_03','S_A03','ST_006', false), 
('S_112622_9_001_002_04','S_A04','ST_006', false), 
('S_112622_9_001_002_05','S_A05','ST_006', false), 
('S_112622_9_001_002_06','S_A06','ST_006', false), 
('S_112622_9_001_002_07','S_A07','ST_006', true), 
('S_112622_9_001_002_08','S_A08','ST_006', false), 
('S_112622_9_001_002_09','S_A09','ST_006', false), 
('S_112622_9_001_002_10','S_A10','ST_006', false), 
('S_112622_9_001_002_11','S_B01','ST_006', false), 
('S_112622_9_001_002_12','S_B02','ST_006', false), 
('S_112622_9_001_002_13','S_B03','ST_006', false), 
('S_112622_9_001_002_14','S_B04','ST_006', false), 
('S_112622_9_001_002_15','S_C01','ST_006', false), 
('S_112622_9_001_002_16','S_C02','ST_006', false), 
('S_112622_9_001_002_17','S_C03','ST_006', false), 
('S_112622_9_001_002_18','S_C04','ST_006', false), 
('S_112622_9_001_002_19','S_D01','ST_006', false), 
('S_112622_9_001_002_20','S_D02','ST_006', true), 
('S_112622_9_001_002_21','S_D03','ST_006', false), 
('S_112622_9_001_002_22','S_D04','ST_006', false), 
('S_112622_9_001_002_23','S_D05','ST_006', false), 
('S_112622_9_001_002_24','S_D06','ST_006', false), 
('S_112622_9_001_002_25','S_D07','ST_006', false), 
('S_112622_9_001_002_26','S_D08','ST_006', false), 
('S_112622_9_001_002_27','S_D09','ST_006', false), 
('S_112622_9_001_002_28','S_D10','ST_006', false);
-- Look into this if we have time- Loading data drom csv
-- LOAD DATA INFILE 'C:\Users\AlexTheGr8\Desktop\MEng\Fall\ENSF614(Advanced_System_Analysis_and_Software_Design)\Project\movie-ticket-reservation-app\database\Seats.csv'
-- INTO TABLE SEATS
-- FIELDS TERMINATED BY ',' ENCLOSED BY '"'
-- LINES TERMINATED BY '\n'
-- IGNORE 1 ROWS
-- (seat_id,theatre_id,movie_id,@show_time,booked)
-- SET show_time = STR_TO_DATE(show_time, '%Y-%m-%d %H:%M');

DROP TABLE IF EXISTS PAYMENT;
CREATE TABLE PAYMENT(
	payment_id 				varchar(255) not null,
    completion_date         datetime not null,	
	primary key (payment_id)
);

INSERT INTO PAYMENT(payment_id, completion_date)
VALUES

('P_0001', '2022-11-22 09:00:00'),
('P_0002', '2022-11-22 09:00:00'),
('P_0003', '2022-11-22 09:00:00'),
('P_0004', '2022-11-22 09:00:00'),
('P_0005', '2022-11-22 09:00:00'),
('P_0006', '2022-11-22 09:00:00'),
('P_0007', '2022-11-22 09:00:00'),
('P_0008', '2022-11-22 09:00:00'),
('P_0009', '2022-11-22 09:00:00'),
('P_0010', '2022-11-22 09:00:00'),
('P_0011', '2022-11-22 09:00:00'),
('P_0012', '2022-11-22 09:00:00'),
('P_0013', '2022-11-22 09:00:00'),
('P_0014', '2022-11-22 09:00:00'),
('P_0015', '2022-11-22 09:00:00'),
('P_0016', '2022-11-22 09:00:00'),
('P_0017', '2022-11-22 09:00:00'),
('P_0018', '2022-11-22 09:00:00');

DROP TABLE IF EXISTS TICKET;
CREATE TABLE TICKET(
	ticket_id 				varchar(255) DEFAULT(uuid()) not null,
	user_id 				varchar(255),
	seat_id 				varchar(255) 	not null,
	-- cost 					decimal(13,2) 	not null,
	is_credited 				boolean DEFAULT(false) not null,
    payment_id				varchar(255) default(uuid()) not null,
	primary key (ticket_id),
	foreign key (seat_id) references SEATS(seat_id),
	foreign key (user_id) references REGISTERED_USER(id)

);

INSERT INTO TICKET (ticket_id, user_id, seat_id, is_credited, payment_id)
VALUES
('TK_0001','U_0001','S_112622_9_001_001_01', false, 'P_0001'),
('TK_0002','U_0002','S_112622_11_002_002_11', false, 'P_0002'),
('TK_0003','U_0002','S_112622_11_002_002_12', false, 'P_0003'),
('TK_0004','U_0002','S_112622_11_002_002_13', false, 'P_0004'),
('TK_0005','U_0002','S_112622_11_002_002_14', false, 'P_0005'),
('TK_0006','U_0003','S_112622_9_003_003_27', true, 'P_0006'),
('TK_0007','U_0003','S_112622_9_003_003_28', true, 'P_0007'),
('TK_0008','U_0003','S_112622_9_003_003_26', true, 'P_0008'),
('TK_0009','U_0003','S_112622_9_003_003_28', false, 'P_0009'),
('TK_0010', 'U_0004','S_112622_9_001_001_06', false, 'P_0010'),
('TK_0011', 'U_0004','S_112622_9_001_001_07', false, 'P_0011'),
('TK_0012', 'U_0004','S_121022_9_002_004_15', false, 'P_0012'),
('TK_0013', 'U_0004','S_121022_9_002_004_16', false, 'P_0013'),
('TK_0014', null,'S_112622_9_001_001_20', true, 'P_0014'),
('TK_0015', null,'S_112622_11_002_002_5', true, 'P_0015'),
('TK_0016', null,'S_112622_9_003_003_4', false, 'P_0016'),
('TK_0017', null,'S_112622_13_003_002_7', false, 'P_0017'),
('TK_0018', null,'S_121022_9_002_004_26', false, 'P_0018');

DROP TABLE IF EXISTS REFUND;
CREATE TABLE REFUND(
	ticket_id 				varchar(255) not null,
	credit_available 		decimal(13,2),
    expiration_date         DateTime not null,	
	primary key (ticket_id),
	foreign key (ticket_id) references TICKET(ticket_id)
);
INSERT INTO REFUND(ticket_id, credit_available, expiration_date)
VALUES
('TK_0006', 3, '2023-11-26 09:00:00'),
('TK_0007', 6, '2023-11-26 09:00:00'),
('TK_0008', 0, '2023-11-26 09:00:00'),
('TK_0014', 4, '2023-11-26 09:00:00'),
('TK_0015', 10, '2023-11-26 09:00:00');




DROP TABLE IF EXISTS REFUND_PAYMENT;
CREATE TABLE REFUND_PAYMENT(
	payment_id              varchar(255) not null, 
    refund_amount			decimal(13, 2) not null,
    refund_ticket_id               varchar(255) not null,
	primary key (payment_id, refund_ticket_id),
	foreign key (refund_ticket_id) references REFUND(ticket_id),
    foreign key (payment_id) references PAYMENT(payment_id)
);

INSERT INTO REFUND_PAYMENT(payment_id, refund_amount, refund_ticket_id)
VALUES
('P_0009', 10, 'TK_0008');

DROP TABLE IF EXISTS CREDIT_PAYMENT;
CREATE TABLE CREDIT_PAYMENT(
	payment_id              varchar(255) not null,  
    amount			        decimal(13, 2) not null,
    credit_card             varchar(255) not null,
	primary key (payment_id),
    foreign key (payment_id) references PAYMENT(payment_id)
);

INSERT INTO CREDIT_PAYMENT(payment_id, amount, credit_card)
VALUES
('P_0001', 10, '1234 9876 0192 8374'),
('P_0002', 10, '1046 2894 9101 3949'),
('P_0003', 10, '1046 2894 9101 3949'),
('P_0004', 10, '1046 2894 9101 3949'),
('P_0005', 10, '1046 2894 9101 3949'),
('P_0006', 10, '9374 0129 0932 5674'),
('P_0007', 10, '9374 0129 0932 5674'),
('P_0008', 10, '9374 0129 0932 5674'),
('P_0010', 10, '1113 1919 9191 1234'),
('P_0011', 10, '1113 1919 9191 1234'),
('P_0012', 10, '1113 1919 9191 1234'),
('P_0013', 10, '1113 1919 9191 1234'),
('P_0014', 10, '3121 5454 5454 4444'),
('P_0015', 10, '3121 5454 5454 4444'),
('P_0016', 10, '3121 5454 5454 4444'),
('P_0017', 10, '3121 5454 5454 4444'),
('P_0018', 10, '3121 5454 5454 4444');


-- UPDATE REFUND SET credit_available = 3 WHERE ticket_id = 'TK_0007';
-- UPDATE REFUND SET credit_available = 6 WHERE ticket_id = 'TK_0006';
-- select * from ticket;
-- select * from seats;
-- select * from REGISTERED_USER;
-- select * from payment;
-- select * from refund;
-- select * from REFUND_PAYMENT;
-- select * from CREDIT_PAYMENT;
