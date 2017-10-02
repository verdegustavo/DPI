select b.*, a.country_code,
       a.country_name,
       a.region_name,
       a.city_name
from ip2location_db5 a, tb_enlaces b
where Dot2LongIP(b.ip_destino) between a.ip_from and a.ip_to;
