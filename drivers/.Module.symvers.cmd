cmd_/home/sarthak/CS614/CS614/A3/crypto_card_driver/drivers/Module.symvers :=  sed 's/ko$$/o/'  /home/sarthak/CS614/CS614/A3/crypto_card_driver/drivers/modules.order | scripts/mod/modpost      -o /home/sarthak/CS614/CS614/A3/crypto_card_driver/drivers/Module.symvers -e -i Module.symvers -T - 
