# What is this thing?

TL;DR: Generate simple links that result in redirection to a URL under your control upon clickage.

This is a simple tool that works similar to Bitly except the user controls both the splash link and redirect URL. An approach such as this is desirable when sending links in a messaging service or application that enforces a length limitation on the or when a complex link may discredit a pretext during social engineering engagements.

It works by bringing a simple HTTP(S) server to a listening state that will use HTML to redirect a user to an upstream URL. It's possible to specify a static splash URL and origin URL for a basic redirect, or a list of redirect URLs can be provided and a unique splash link will be generated and printed to stdout. All simplified links are derived from the user-supplied splash-url and no restrictions are enforced on redirect URLs.

# Installation

*Python3.6 or newer is required*. For all other requirements: ```python3.6 -m pip install -r requirements.txt```

# Useful Features

Below are a few useful features of this adorable little programming project.

## Redirect URL File Monitoring (Add Redirect URLs w/o Restarting the Server)

A distinct process runs in the background and monitors the input file for new redirect urls, which will then result in new splash links being written to stdout. This means that new targets can be added without restarting the server. Simply append a new record to the input file and the script will handle the rest, e.g. ```echo https://fs.targetdomain.com?user=newuser >> redirect_urls``` will result in a new splash link being written to stdout.

- If you just want the links written to stdout, use the ```-dl``` flag to dump all splash links and origin URLs from the database and exit.
- Link printing can be suppressed during normal operation using the ```-sl``` flag.

## Access Logs

The script inserts all URLs into an SQLite database and creates access logs tracking the time of access and source IP address.

- Use the ```-da``` flag to dump access logs from the database (You'll need to supply required arguments as well).

```
python3.7 simple_redirect.py --splash-url https://hr.phishingdomain.net --redirect-url-file redirect_urls.txt --redirect-url https://fs.targetdomain.com -da

Initializing a Simple Redirector

[+] Dumping access logs to stdout
------------------------------------------------------------
- Splash Link: https://hr.phishingdomain.net?sid=5747
- Redirect URL: https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=vic2@targetdomain.com&mkt=&lc=
- Access Logs:

[1][2019-03-05 01:38:37] 192.168.86.2
------------------------------------------------------------
[+] Exiting
```

## Examples

### Single Redirection URL

If we want to redirect all users to Google from mydomain.com, just run: ```simple_redirect.py --splash-url http://www.mydomain.com --redirect-url https://www.google.com``` 

```
python3.7 simple_redirect.py --splash-url https://hr.phishingdomain.com --redirect-url https://www.google.com
    
Initializing a Simple Redirector

[+] Beginning static redirection to > https://www.google.com
[+] Access logging will not occur
[+] Dumping known URLS and Starting the HTTP server
```

### Configuring wth HTTPS

If we want to do a single redirect with TLS1.2, just run: ```simple_redirect.py --splash-url https://www.mydomain.com --redirect-url https://www.google.com --cert-file cert.pem --key-file key.pem```

### Multiple Redirection URLs

The real value with this script becomes evident when we feed it multiple redirect URLs, each of which will be translated to concise URLs suffixed only with a unique integer parameter.

For the sake of simplicity, let's say we're targeting users of ```targetdomain.com``` for attack and we want to have victims authenticate to an upstream ADFS server through Modlishka. We can craft some links with custom URL parameters to make the attack more authentic by molding it to our pretext. ADFS endpoints will take the value from the ```username``` parameter and pre-fill it in the username field of the authentication form. Here is the base link we'll be working with (note that it's quite ugly):


    https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=<USERNAME_HERE>&mkt=&lc=


Now let's generate some sample URLS for the grins and use the output as the ```--redirect-url-file``` parameter.

    for u in {vic1,vic2,vic3}; do echo $URL | sed -r -r "s/<USERNAME>/$u@targetdomain.com/g" >> redirect_urls.txt; done

Now we can run the following command to have the script bring the server online and give us some fresh and concise splash links along with the full redirect URL for reference. Visiting the splash link will result in immediate redirection to the redirect link with the username field pre-populated.

```
python3.7 simple_redirect.py --splash-url https://hr.phishingdomain.net --redirect-url-file redirect_urls.txt --redirect-url https://fs.targetdomain.com --cert-file cert.pem --key-file key.pem

Initializing a Simple Redirector

[+] Starting URL watcher process
[+] Watching URL file: redirect_urls.txt
[+] To avoid having to restart the server, append new URLs to the file above for new links to be generated and printed to stdout
----------------------------------------------------
- Splash Link: https://hr.phishingdomain.net?sid=24225
- Redirect URL: https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=<USERNAME>&mkt=&lc=
----------------------------------------------------

----------------------------------------------------
- Splash Link: https://hr.phishingdomain.net?sid=22401
- Redirect URL: https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=vic1@targetdomain.com&mkt=&lc=
----------------------------------------------------

----------------------------------------------------
- Splash Link: https://hr.phishingdomain.net?sid=87071
- Redirect URL: https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=vic2@targetdomain.com&mkt=&lc=
----------------------------------------------------

----------------------------------------------------
- Splash Link: https://hr.phishingdomain.net?sid=84579
- Redirect URL: https://fs.targetdomain.com/adfs/ls/?client-request-id=826a908e-c842-488c-8ade-3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMRd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmOhPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9wF20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13UcJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJbqnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7BVkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1eloCo8-tNknpdlA0gGgB2fgM1&cbcxt=&username=vic3@targetdomain.com&mkt=&lc=
----------------------------------------------------

[+] Dumping known URLS and Starting the HTTP server
[+] Wrapping the HTTP server socket in TLS1.2
```

# Basic Terminology

Below are a series of parameters that may be somewhat confusing due to naming conventions. This should provide some level of clarity.

- ```splash_link``` - A link intended to be delivered to some user. Typically shortened or simplified and crafted to support the pretext of a given social engineering engagement.
- ```redirect_url``` - The URL that is returned in the body of the HTTP response that the browser will be redirected to. This parameter is also the default URL that a user will be delivered to should an unknown request be sent to the HTTP server.
- ```redirect_file``` - A file containing a series of redirect URLs that will be imported to the SQLite database file.

# Help Interface

    usage: Redirector thingy [-h] [--interface INTERFACE] [--port PORT]
                             [--cert-file CERT_FILE] [--key-file KEY_FILE]
                             [--db-file DB_FILE] --splash-url SPLASH_URL
                             [--id-param ID_PARAM] --redirect-url REDIRECT_URL
                             [--redirect-url-file REDIRECT_URL_FILE]
                             [--dump-links] [--dump-access-logs]
                             [--suppress-link-output]

    Redirection, etc.

    optional arguments:
      -h, --help            show this help message and exit
      --interface INTERFACE, -i INTERFACE
                            Interface/IP address the server will bind to.
      --port PORT, -p PORT  Port the server will listen on.
      --cert-file CERT_FILE, -c CERT_FILE
                            Certificate file for the server to uce
      --key-file KEY_FILE, -k KEY_FILE
                            Keyfile corresponding to certificate file
      --db-file DB_FILE, -db DB_FILE
                            Path to the appropriate SQLite file
      --splash-url SPLASH_URL, -su SPLASH_URL
                            URL which the id_param will be suffixed to.
      --id-param ID_PARAM, -ip ID_PARAM
                            Name of the parameter that will be suffixed to the
                            link URL.
      --redirect-url REDIRECT_URL, -ru REDIRECT_URL
                            Single or default url which targets will be redirected
      --redirect-url-file REDIRECT_URL_FILE, -ruf REDIRECT_URL_FILE
                            Newline delimited file containing origin URLs that
                            will be mapped back to a unique splash link
      --dump-links, -dl     Just dump splash links from the database.
      --dump-access-logs, -da
                            Dump access logs from the database
      --suppress-link-output, -sl
                            Suppress printing of links to stdout. Run the script
                            again using the --dump-links flag to obtain links when
                            using this option
