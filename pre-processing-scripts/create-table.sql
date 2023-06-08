create schema malware;

create table malware.malware_data_filtered
(
    country text,
    datetime text,
    delivery_method text,
    file_size bigint,
    file_type text,
    malware_type text,
    month integer,
    num_detections integer,
    num_week integer,
    sha1_hash text not null
        constraint "malware-data-filtered_pkey"
            primary key,
    year integer
);