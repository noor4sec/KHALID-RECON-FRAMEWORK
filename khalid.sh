#! /bin/bash 
target=$1

echo "
_  ___   _    _    _     ___ ____        ____  _____ ____ ___  _   _       
| |/ / | | |  / \  | |   |_ _|  _ \      |  _ \| ____/ ___/ _ \| \ | |      
| ' /| |_| | / _ \ | |    | || | | |_____| |_) |  _|| |  | | | |  \| |_____ 
| . \|  _  |/ ___ \| |___ | || |_| |_____|  _ <| |__| |__| |_| | |\  |_____|
|_|\_\_| |_/_/   \_\_____|___|____/      |_| \_\_____\____\___/|_| \_|      
                                                                            
 _____ ____      _    __  __ _______        _____  ____  _  __
|  ___|  _ \    / \  |  \/  | ____\ \      / / _ \|  _ \| |/ /
| |_  | |_) |  / _ \ | |\/| |  _|  \ \ /\ / / | | | |_) | ' / 
|  _| |  _ <  / ___ \| |  | | |___  \ V  V /| |_| |  _ <| . \ 
|_|   |_| \_\/_/   \_\_|  |_|_____|  \_/\_/  \___/|_| \_\_|\_\
                                                              
"
echo "        @Khalid Cyber Security"

if [ ! -d "$target" ]; then
      mkdir $target
fi
if [ ! -d "$target/recon" ]; then
      mkdir $target/recon
fi

if [ ! -d "$target/params-vuln" ]; then
          mkdir $target/params-vuln
fi

if [ ! -d "$target/subs-vuln" ]; then
          mkdir $target/subs-vuln
fi

if [ ! -d "$target/subs-vuln/false-positive" ]; then
          mkdir $target/subs-vuln/false-positive
fi

if [ ! -d "$target/params-vuln/false-positive" ]; then
          mkdir $target/params-vuln/false-positive
fi

#---------------------------------------------------------------------------------
#-----------------------------Finding SubDomains----------------------------------
#----------------------------------------------------------------------------------
echo "[+]Enumurating SubDomains Using Amass..." 
amass enum -d $target >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Assetfinder..." 
assetfinder $target >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using SubFinder..."
subfinder -d $target -o $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Findomain..." 
findomain -t $target -q >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Sublist3r..."
python3 /opt/Sublist3r/sublist3r.py -d $target -o $1/recon/subs.txt

echo "[+]Filtering Repeated Domains..." 
cat $target/recon/subs.txt | grep $target | sort -u | tee $target/recon/final-subs.txt 
rm $target/recon/subs.txt

echo "[+]Total Unique SubDomains" 
cat $target/recon/final-subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Filtering Live SubDomains--------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Removing Dead Domains Using httpx....." 
$target/recon/final-subs.txt  | httpx --silent  >> $target/recon/live-check.txt

echo "[+]Removing Dead Domains Using httprobe....." 
$target/recon/final-subs.txt  | httprobe >> $target/recon/live-check.txt

echo "[+]Analyzing Both httpx && httprobe...."
cat $target/recon/live-check.txt | sed 's/https\?:\/\///' | sort -u | tee $target/recon/live-subs.txt 
rm $target/recon/live-check.txt

echo "[+]Total Unique Live SubDomains...."
cat $target/recon/live-subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Enumurating Parameters-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Enumurating Params From Paramspider...." 
python3 /opt/ParamSpider/paramspider.py --level high -d $target -p khalid -o $1/recon/test-params.txt
echo "[+]Enumurating Params From Waybackurls...." 
cat $1/recon/live-subs.txt | waybackurls | grep = | qsreplace khalid | sort -u >> $1/recon/test-params.txt
echo "[+]Enumurating Params From gau Tool...." 
gau --subs  $target  | grep = | qsreplace khalid | sort -u >> $1/recon/test-params.txt
echo "[+]Enumurating Params From gauPlus Tool...." 
cat $target/recon/live-subs.txt | gauplus | grep = | qsreplace khalid | sort -u >> $1/recon/test-params.txt

echo "[+]Filtering Dups..." 
$1/recon/test-params.txt | sort -u | tee $target/recon/final-params.txt 

rm $1/recon/test-params.txt

echo "[+]Total Unique Params Found...." 
cat $target/recon/final-params.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing For Open Redirects----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Openredirects...." 
cat $target/recon/final-params.txt | qsreplace 'https://evil.com' | while read host do ; do curl -s -L $host -I | grep "https://evil.com" && echo "$host" ; done >> $target/params-vuln/open-redirects.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For HTMLi Injection---------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For HTML Injection...." 
cat $target/recon/final-params.txt | qsreplace '"><u>hyper</u>' | tee $target/recon/htmli-test.txt && cat $target/recon/htmli-test.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<u>hyper</u>" && echo "$host" ; done >> $target/params-vuln/htmli.txt
rm $target/recon/htmli-test.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For XSS Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+]Testing For XSS Injection...." 
#dalfox file $url/htmli.txt -o $url/xss.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Command Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Command Injection...." 
python3 /opt/commix/commix.py -m $target/recon/final-params.txt --batch 
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For CRLF Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For CRLF Injection...." 
crlfuzz -l $target/recon/final-params.txt -o $target/params-vuln/crlf.txt -s 
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For SQL Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SQL Injection...." 
cat $target/recon/final-params.txt | python3 /opt/sqlmap/sqlmap.py --level 2 --risk 2 
#--------------------------------------------------------------------------------------------------
#-----------------------------------Checking For SSRF----------------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For External SSRF.........." 
cat $target/recon/final_params.txt | qsreplace "https://noor.requestcatcher.com/test" | tee $target/recon/ssrftest.txt && cat $target/recon/ssrftest.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "request caught" && echo "$host"; done >> $url/params-vuln/eSSRF.txt
rm $target/recon/ssrftest.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For XXE Injection----------------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Local File Inclusion----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Scanning For Local File Inclusion...."
cat $target/recon/final-params.txt | qsreplace FUZZ | while read host ; do ffuf -u $host -v -mr "root:x" -w /opt/payloads/lfi-small.txt ; done > $1/params-vuln/lfi.txt
#--------------------------------------------------------------------------------------------------
#-------------------------Checking For Server Side Template Injection-----------------------------
#--------------------------------------------------------------------------------------------------



#--------------------------------------------------------------------------------------------------
#-------------------------Fuzzing Params With Nuclei ----------------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing Params With Nuclei Fuzzing Templates..."
cat $target/recon/final-params.txt | nuclei -t /root/fuzzing-templates >> $target/params-vuln/nuclei.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Scannning HTTP Parameter Smuggling---------------------------------
#--------------------------------------------------------------------------------------------------
#figlet "Fuzzing Domains"
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For SubDomain TakeOver------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SubTakeOver" 
subzy --targets  $url/recon/final_subs.txt  --hide_fails >> $target/sub_take_over.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Full Scan With Nuclei----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+] Full Scan With Nuclei......." 
cat $1/recon/live-subs.txt | nuclei -t /root/nuclei-templates/ >> $1/subs-vuln/nuclei.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Full Scan With Nikto----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+] Full Scan With Nikto...." 
nikto -h $target/recon/live-subs.txt > $target/subs-vuln/nikto.txt
#------------------------------------------------------------------------------------------------------------
#----------------------------------------------Checking For CORS---------------------------------------------
#------------------------------------------------------------------------------------------------------------
#echo "[+]Checking For CORS...." | lolcat
#cat $url/recon/live_subs.txt | while read host do ; do curl $host --silent --path-as-is --insecure -L -I -H Origin:beebom.com | grep "beebom.com" && echo "$host" ; done >> $url/subs_vuln/cors.txt
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Checking For XSS through Referer Header-------------------------------
#------------------------------------------------------------------------------------------------------------
echo "[+]Checking For Xss in Referer Header...." | lolcat
cat $target/recon/live-subs.txt | while read host do ; do curl $host --silent --path-as-is --insecure -L -I -H Referer: https://beebom.com/ | grep "beebom.com" && echo "$host" ; done >> $url/subs-vuln/xss-refer.txt

figlet "Recon v2"

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Taking LiveSubs ScreenShots-------------------------------------------
#------------------------------------------------------------------------------------------------------------
#echo "[+]Taking ScreenShots For Live Websites..." 
#python3 /opt/EyeWitness/Python/EyeWitness.py --web -f $url/recon/livesubs.txt --no-prompt -d $1/recon/EyeWitness --resolve --timeout 240
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Whois-------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Headers--------------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Emails & passwords-------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For WAF -------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Built-in-with--------------------------------------------
#------------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Open Ports--------------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+] Scanning for open ports..."
#nmap -iL $url/recon/live_subs.txt -T4 -oA $url/recon/openports.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing For GitHub Recon----------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+] Fuzzing For GitHub Recon"





