#include "testutils.h"

int
test_main(void)
{
  test_sign("DSA signing",
	    S("{KDM6ZHNhKDE6cDEyODqD2afCziqRefQ82zv/594PDu8m3V365E1TG8DeRWNN"
 	      "LAfLkpsNvhDaWABw5qv7uEFcRL/1cLitd532U6rZfce964FdfogQPmFgbtPY"
 	      "opX7/TQNLUniIIM+us5VEeIsTwKX7TUemUj6hI6cj623tHvMR970JVteHV4Q"
 	      "IVs7VaC4XykoMTpxMjA6gmbg3q9GAgukjUEMpYDzqXhim10pKDE6ZzEyODow"
 	      "00u583a+yUcVSv5Adrx9NZydMvVHHdu+jWqUHEf6ncTzJXMVHbtKpZ65ibdK"
 	      "w2u2MQpei1gFAWVdkfOT2qGTrhMDBJuH/rsJPcBAS1O0xdokYzAPnFsVbXiM"
 	      "Ss6Oy7ndAMGNmVN/JVrAJdB02JSmB8vjAjoSdu9VaRajP33lQykoMTp5MTI4"
 	      "OmRAIEiyfzn0BKVGqEkJycDp4t0VOoSZRhBiiSWY0wryeuPO/CtwD7bQdzkK"
 	      "g73K14oSmUh8liO7Yq8MhaPfnvHuLA1mZY4f0yg7VAf2zTDufmFU+tQaaosP"
 	      "XIbFrMwRJ798ml1rrcsBIYDLYqVcXhfW01KM2+ACzO4THBuGhn96KSgxOngy"
 	      "MDpWxu+vh40G7vIdwHD6tx2m7B4wpikp}"),
	    S("Needs some randomness."),
	    NULL);
  SUCCESS();
}
