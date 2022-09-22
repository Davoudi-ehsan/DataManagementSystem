

MAIN_TABLES = {}

MAIN_TABLES['all_devices_information'] = '''
CREATE TABLE `testdb`.`all_devices_information` (
  `id` VARCHAR(15) NOT NULL COMMENT 'unique serial number of device',
  `type` TINYINT UNSIGNED NULL DEFAULT 0 COMMENT 'type of physical device',
  `gateway_id` VARCHAR(15) NOT NULL COMMENT 'serial number of gateway which device connected by',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
  COMMENT = 'list of all devices connected to datamanagement system';
'''

MAIN_TABLES['gateways_information'] = '''
CREATE TABLE `testdb`.`gateways_information` (
  `id` VARCHAR(15) NOT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT FALSE,
  `last_ip_address` VARCHAR(15) NULL,
  `simcard_number` VARCHAR(14) NULL,
  `location_lat` FLOAT NULL,
  `location_long` FLOAT NULL,
  `physical_device_information` JSON NULL,
  `server_key` VARCHAR(10) NULL,
  `client_key` VARCHAR(10) NULL,
  `apn` VARCHAR(20) NULL,
  `reference_ip` VARCHAR(15) NULL,
  `reference_port` SMALLINT NULL,
  `last_connection_time` INT NOT NULL DEFAULT 1616334000,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  UNIQUE INDEX `simcard_number_UNIQUE` (`simcard_number` ASC) VISIBLE,
  UNIQUE INDEX `client_key_UNIQUE` (`client_key` ASC) VISIBLE,
  PRIMARY KEY (`id`))
  COMMENT = 'list of all gateways connected to datamanagement system';
'''

MAIN_TABLES['controllers_information'] = '''
CREATE TABLE `testdb`.`controllers_information` (
  `id` VARCHAR(15) NOT NULL,
  `readout_profile_objects` JSON NULL,
  `data_profile_1_objects` JSON NULL,
  `data_profile_2_objects` JSON NULL,
  `data_profile_3_objects` JSON NULL,
  `data_profile_4_objects` JSON NULL,
  `local_com_interface_mode` ENUM('TORAL', 'EN13757', 'HDLC', 'IEC') NULL DEFAULT 'TORAL',
  `local_com_interface_baud` ENUM('300', '600', '1200', '2400', '4800', '9600') NULL DEFAULT '9600',
  `connected_devices_profile` JSON NULL,
  `assigned_accounts_profile` JSON NULL,
  `disconnectors_profile` JSON NULL,
  `limiters_profile` JSON NULL,
  `alarm_registers_profile` JSON NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE);
'''

MAIN_TABLES['emeters_information'] = '''
CREATE TABLE `testdb`.`emeters_information` (
  `id` VARCHAR(15) NOT NULL,
  `capture_buffer_objects` JSON NULL,
  `mode` ENUM('HDLC', 'IEC') NULL,
  `baud` ENUM('300', '600', '1200', '2400', '4800', '9600') NULL DEFAULT '9600',
  `primary_address` VARCHAR(15) NULL,
  `manufacturer_id` SMALLINT NULL,
  `active_forward_energy_profile` JSON NULL,
  `reactive_forward_energy_profile` JSON NULL,
  `power_quality_profile` JSON NULL,
  `active_enery_profile` JSON NULL,
  `alarm_registers_profile` JSON NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE);
'''

MAIN_TABLES['wmeters_information'] = '''
CREATE TABLE `testdb`.`wmeters_information` (
  `id` VARCHAR(15) NOT NULL,
  `capture_buffer_objects` JSON NULL,
  `mode` ENUM('EN13757', 'MODBUS') NULL DEFAULT 'EN13757',
  `baud` ENUM('300', '600', '1200', '2400', '4800', '9600') NULL DEFAULT '9600',
  `primary_address` TINYINT UNSIGNED NULL DEFAULT 1,
  `manufacturer_id` SMALLINT NULL,
  `accomulative_forward_volume` INT NULL,
  `accomulative_backwards_volume` INT NULL,
  `waterflow_characteristics` JSON NULL,
  `alarm_registers_profile` JSON NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE);
'''

ADDITIVE_TABLES = {}

ADDITIVE_TABLES['gateway'] = '''
CREATE TABLE XX (
  `ip_address` VARCHAR(15) NULL,
  `packet_direction` ENUM('StoC', 'CtoS') NULL,
  `packet_contents` VARCHAR(1024) NULL,
  `timestamp` INT NOT NULL DEFAULT 1616334000);
'''

ADDITIVE_TABLES['controller'] = '''
CREATE TABLE XX (
  `alarm_register_1` VARCHAR(10) NULL,
  `alarm_register_2` VARCHAR(10) NULL,
  `alarm_register_3` VARCHAR(10) NULL,
  `alarm_register_4` VARCHAR(10) NULL,
  `alarm_register_5` VARCHAR(10) NULL,
  `readout_profile_values` JSON NULL,
  `data_profile_1_values` JSON NULL,
  `data_profile_2_values` JSON NULL,
  `data_profile_3_values` JSON NULL,
  `data_profile_4_values` JSON NULL,
  `disconnector_activity` JSON NULL,
  `timestamp` INT NOT NULL DEFAULT 1616334000);
'''

ADDITIVE_TABLES['emeter'] = '''
CREATE TABLE XX (
  `alarm_register_1` VARCHAR(10) NULL,
  `alarm_register_2` VARCHAR(10) NULL,
  `alarm_register_3` VARCHAR(10) NULL,
  `alarm_register_4` VARCHAR(10) NULL,
  `alarm_register_5` VARCHAR(10) NULL,
  `active_forward_energy_total` INT NULL,
  `active_forward_energy_t1` INT NULL,
  `active_forward_energy_t2` INT NULL,
  `active_forward_energy_t3` INT NULL,
  `active_forward_energy_t4` INT NULL,
  `reactive_forward_energy_total` INT NULL,
  `reactive_forward_energy_t1` INT NULL,
  `reactive_forward_energy_t2` INT NULL,
  `reactive_forward_energy_t3` INT NULL,
  `reactive_forward_energy_t4` INT NULL,
  `max_active_forward_power` INT NULL,
  `max_reactive_forward_power` INT NULL,
  `instant_current_l1` SMALLINT NULL,
  `instant_current_l2` SMALLINT NULL,
  `instant_current_l3` SMALLINT NULL,
  `instant_voltage_l1` SMALLINT NULL,
  `instant_voltage_l2` SMALLINT NULL,
  `instant_voltage_l3` SMALLINT NULL,
  `max_active_power` INT NULL,
  `active_energy_total` INT NULL,
  `active_energy_t1` INT NULL,
  `active_energy_t2` INT NULL,
  `active_energy_t3` INT NULL,
  `active_energy_t4` INT NULL,
  `timestamp` INT NOT NULL DEFAULT 1616334000);
'''

ADDITIVE_TABLES['wmeter'] = '''
CREATE TABLE XX (
  `alarm_register_1` VARCHAR(10) NULL,
  `alarm_register_2` VARCHAR(10) NULL,
  `alarm_register_3` VARCHAR(10) NULL,
  `alarm_register_4` VARCHAR(10) NULL,
  `alarm_register_5` VARCHAR(10) NULL,
  `accomulative_forward_value` INT NULL,
  `accomulative_backward_value` INT NULL,
  `instant_flowrate` SMALLINT NULL,
  `instant_temperature` SMALLINT NULL,
  `timestamp` INT NOT NULL DEFAULT 1616334000);
'''

ADDITIVE_TABLES['account'] = '''
CREATE TABLE XX (
  `available_credit` INT NULL,
  `current_credit_amount` SMALLINT NULL,
  `credit_exhausted` TINYINT NULL,
  `timestamp` INT NOT NULL DEFAULT 1616334000);
'''

INSERT = '''
INSERT INTO all_devices_information (id,type,gateway_id) VALUES ('2201', 1, '2201');
'''
