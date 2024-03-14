#!/usr/bin/python
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>
# ----------------------------------------------------------------------
# @author Chamli Mohamed 14|06|2016
import json
import os
import pathlib
import sys
import locale
import subprocess
import re
import platform
import inspect
import argparse
import requests
import time
from fake_useragent import UserAgent
from requests_ntlm import HttpNtlmAuth
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
import sys
from io import StringIO
from urllib3.exceptions import InsecureRequestWarning

# from libs.colorama import Fore, Back, Style
from libs import FileUtils
from libs.tldextract import *

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.5'
__description__ = '''\
  ___________________________________________

  CyberCrowl scan | v.''' + __version__ + '''
  Author: Chamli Mohamed
  Github: https://github.com/chamli
  ___________________________________________
'''


# Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
def get_revision_number():
    ret_val = None
    file_path = None
    _ = os.path.dirname(__file__)

    while True:
        file_path = os.path.join(_, ".git", "HEAD")
        if os.path.exists(file_path):
            break
        else:
            file_path = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)

    while True:
        if file_path:
            if os.path.isfile(file_path):
                with open(file_path, "r") as f:
                    content = f.read()
                    file_path = None
                    if content.startswith("ref: "):
                        file_path = os.path.join(_, ".git", content.replace("ref: ", "")).strip()
                    else:
                        match = re.match(r"(?i)[0-9a-f]{32}", content)
                        ret_val = match.group(0) if match else None
                        break
        else:
            break

    if not ret_val:
        process = subprocess.Popen("git rev-parse --verify HEAD", shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        ret_val = match.group(0) if match else None

    return ret_val[:7] if ret_val else None


# unicode representation of the supplied value
def get_unicode(value, encoding=None, none_to_null=False):
    if none_to_null and value is None:
        return None

    if isinstance(value, str):
        return value
    # elif isinstance(value, basestring):
    #     while True:
    #         try:
    #             return str(value, encoding or "utf8")
    #         except UnicodeDecodeError, ex:
    #             try:
    #                 return str(value)
    #             except:
    #                 value = value[:ex.start] + "".join(r"\x%02x" % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    else:
        try:
            return str(value)
        except UnicodeDecodeError:
            return str(value)


# get directory path CyberCrowl
def module_path():
    we_are_frozen = hasattr(sys, "frozen")

    try:
        _ = sys.executable if we_are_frozen else __file__
    except NameError:
        _ = inspect.getsourcefile(module_path)

    return get_unicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or "utf8")


# update tool
def update():
    success = False
    git_rep = "git://github.com/chamli/CyberCrowl.git"
    tool_path = module_path()

    if not os.path.exists(os.path.join(tool_path, ".git")):
        err_msg = "not a git repository. Please checkout the 'CyberCrowl' repository "
        write(err_msg)
        return
    else:
        info_msg = "updating CyberCrowl to the latest development version from the "
        info_msg += "GitHub repository"
        write(info_msg)

        debug_msg = "CyberCrowl will try to update itself using 'git' command"
        write(debug_msg)

        try:
            process = subprocess.Popen("git checkout . && git pull %s HEAD" % git_rep, shell=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       cwd=tool_path.encode(locale.getpreferredencoding()))
            stdout, stderr = process.communicate()
            success = not process.returncode
        except (IOError, OSError) as ex:
            success = False
            write(ex)
            return

        if success:
            write("%s the latest revision '%s'" % (
                "already at" if "Already" in stdout else "updated to", get_revision_number()))
            return
        else:
            if "Not a git repository" in stderr:
                err_msg = "not a valid git repository. Please checkout the 'CyberCrowl' repository "
                err_msg += "from GitHub (e.g. 'git clone --depth 1 https://github.com/chamli/CyberCrowl.git CyberCrowl')"
                write(err_msg)
                return
            else:
                write("update could not be completed ('%s')" % re.sub(r"\W+", " ", stderr).strip())
                return

    if not success:
        if platform.system() == 'Windows':
            info_msg = "for Windows platform it's recommended "
            info_msg += "to use a GitHub for Windows client for updating "
            info_msg += "purposes (http://windows.github.com/) or just "
            info_msg += "download the latest snapshot from "
            info_msg += "https://github.com/chamli/CyberCrowl/archive/master.zip"
        else:
            info_msg = "for Linux platform it's required "
            info_msg += "to install a standard 'git' package (e.g.: 'sudo apt install git')"

        write(info_msg)
        return

def write(string):
    if platform.system() == 'Windows':
        sys.stdout.write(string)
        sys.stdout.flush()
        sys.stdout.write('\n')
        sys.stdout.flush()
    else:
        sys.stdout.write(string + '\n')
    sys.stdout.flush()
    sys.stdout.flush()


# check url work
def check_url(url):
    # check
    try:
        ress1 = requests.head(url, allow_redirects=True)

        if url != ress1.url:
            return "Maybe you should use ;" + ress1.url
        else:
            ress = requests.get(url)
            code = ress.status_code
            if code == 200:
                return True
            else:
                return False

    except (requests.exceptions.ConnectionError, requests.exceptions.MissingSchema):
        print("Try a different url please")
        return False
    except Exception:
        return False


# read url
def read(url, result):
    ret = check_url(url)
    url_ok = False
    if "Maybe" in str(ret):
        url_ok = True
        url = ret.rsplit(';', 1)[1]
    if not ret and not url_ok:
        message = "Check url (ex: https://github.com) " + (ret if "Try" in str(ret) else "")
        message = "\n\n" "[-]" + message
        result['message'] = 'The url has either moved or been entered incorrectly.'
        write(message)
        return result

    # print Target
    message = '\nTarget: {0}\n'.format(url)
    write(message)

    return url


# crawl directory
def crowl(dirs, url, args, result):
    # args strings
    domain = args.url
    w_list = args.wordlist
    delay = args.delay
    random_agent = args.randomAgent
    auth_type = args.authType.lower() if args.authType is not None else ""
    auth_cred = "".join(args.authCred).rsplit(':') if args.authCred is not None else ""
    proxy = "".join(args.proxy) if args.proxy is not None else None

    # init count valid url
    count = 0

    # get domain
    extracted = tldextract.extract(url)
    domain = "{}.{}".format(extracted.domain, extracted.suffix)

    if not os.path.exists("reports"):
        os.makedirs("reports")
    logfile = open("reports/" + domain + "_logs.txt", "w+")

    # init user agent
    if random_agent:
        ua = UserAgent()

    # init default user agent    
    headers = {'User-Agent': 'CyberCrowl'}

    # init default proxy 
    proxies = {"http": proxy, "https": proxy}

    for dir in dirs:

        dir = dir.replace("\n", "")
        dir = "%s" % (dir)

        res = ""
        save = 0
        if url.endswith('/'):
            f_url = url + dir
        else:
            f_url = url + "/" + dir

        # add cookie header

        if random_agent:
            headers = {'User-Agent': ua.random}

        # make request with different type of authentication
        if auth_type == "basic":
            proxy_err = "Check your proxy please! "
            conn_err = "Error Connecting!"
            try:
                ress = requests.get(f_url, headers=headers, auth=HTTPBasicAuth(auth_cred[0], auth_cred[1]),
                                    allow_redirects=False, proxies=proxies, verify=False)
            except requests.exceptions.ConnectionError:
                write(conn_err)
                result['message'] = conn_err
                return
            except requests.exceptions.ProxyError:

                write(proxy_err)
                result['message'] = proxy_err
                return

        elif auth_type == "digest":
            try:
                ress = requests.get(f_url, headers=headers, auth=HTTPDigestAuth(auth_cred[0], auth_cred[1]),
                                    allow_redirects=False, proxies=proxies, verify=False)
            except requests.exceptions.ConnectionError:
                write(conn_err)
                result['message'] = conn_err
                return
            except requests.exceptions.ProxyError:
                write(proxy_err)
                result['message'] = proxy_err
                return

        elif auth_type == "ntlm":
            try:
                ress = requests.get(f_url, headers=headers, auth=HttpNtlmAuth(auth_cred[0], auth_cred[1]),
                                    allow_redirects=False, proxies=proxies, verify=False)
            except requests.exceptions.ConnectionError:
                write(conn_err)
                result['message'] = conn_err
                return
            except requests.exceptions.ProxyError:
                write(proxy_err)
                result['message'] = proxy_err
                return

        else:
            try:
                ress = requests.get(f_url, headers=headers, allow_redirects=False, verify=False)
            except requests.exceptions.ConnectionError:
                write(conn_err)
                result['message'] = conn_err
                return
            except requests.exceptions.ProxyError:
                write(proxy_err)
                result['message'] = proxy_err
                return

        response = ress.status_code

        # size
        try:
            if ress.headers['content-length'] is not None:
                size = int(ress.headers['content-length'])
            else:
                size = 0

        except (KeyError, ValueError, TypeError):
            size = len(ress.content)
        finally:
            f_size = FileUtils.sizeHuman(size)

        # check response
        if response == 200 or response == 302 or response == 304:
            res = "[+] %s - %s : HTTP %s Found" % (f_url, f_size, response)

            obj = {
                "url": f_url,
                "size": f_size,
                "response": response,
            }

            if 'urls' not in result:
                result['urls'] = []

            result['urls'].append(obj)

            save = 1
            count += 1

            # # To check quickly:
            # break

        elif response == 301:
            res = "[-] %s - %s : HTTP %s : Moved Permanently" % (f_url, f_size, response)
        elif response == 401:
            res = "[-] %s - %s : HTTP %s : Unauthorized" % (f_url, f_size, response)
        elif response == 403:
            res = "[-] %s - %s : HTTP %s : Needs authorization" % (f_url, f_size, response)
        elif response == 404:
            res = "[-] %s - %s : HTTP %s : Not Found" % (f_url, f_size, response)
        elif response == 405:
            res = "[-] %s - %s : HTTP %s : Method Not Allowed" % (f_url, f_size, response)
        elif response == 406:
            res = "[-] %s - %s : HTTP %s : Not Acceptable" % (f_url, f_size, response)
        elif response == 429:
            res = "[-] %s - %s : HTTP %s : Too Many Requests" % (f_url, f_size, response)
        elif response == 503:
            res = "[-] %s - %s : HTTP %s : Service Unavailable" % (f_url, f_size, response)
        else:
            res = "[-] %s - %s : HTTP %s : Unknown response" % (f_url, f_size, response)

        # print result
        if response != "":
            write(res)

        # save founded url log
        if save == 1:
            found = url + dir
            logfile.writelines(found + "\n")

        if delay > 0:
            time.sleep(float(delay))
            print("Sleeping for %s seconds" % str(delay))

    write("\n\n[+]Found : %s directory" % (count))
    result['message'] = f'Found {count} directory'
    logfile.close()
    return result


def main():

    global list
    result = {}

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        prog='CyberCrowl',
        description=__description__,
        epilog='''\
    EXAMPLE:
    web site scan with internal wordlist
      cybercrowl -u www.domain.com
    web site scan with external wordlist
      cybercrowl -u www.domain.com -w wordlist.txt
                '''
    )

    parser.add_argument('-u', dest='url', help='specific target url, like domain.com', type=str)

    parser.add_argument('--output-file', help='Path to output file', type=pathlib.Path)

    parser.add_argument('-w', help='specific path to wordlist file',
                        nargs=1, dest='wordlist', type=str, required=False)

    parser.add_argument('-d', help='add delay between requests',
                        nargs=1, dest='delay', type=float, default=0)

    parser.add_argument('--random-agent', dest="randomAgent",
                        help='Use randomly selected HTTP User-Agent header value',
                        action='store_true')

    parser.add_argument('--update', dest="update",
                        help='Update CyberCrowl',
                        action='store_true')

    parser.add_argument("--auth-type", dest="authType",
                        nargs='?', type=str, help="HTTP authentication type ""(Basic, Digest or NTLM)",
                        required=False)

    parser.add_argument("--auth-cred", dest="authCred",
                        nargs=1, type=str, help="HTTP authentication credentials ""(name:password)", required=False)

    parser.add_argument("--proxy", dest="proxy",
                        nargs=1, type=str, help="Use a proxy to connect to the target URL", required=False)

    args = parser.parse_args()

    # update version
    if args.update:
        update()

    required_together = ('authType', 'authCred')

    # args.authType will be None if authType is not provided
    if any([getattr(args, x) for x in required_together]):
        if not all([getattr(args, x) for x in required_together]):
            write("Cannot supply --auth-type without --auth-cred")
            return

    # args strings
    domain = args.url
    w_list = args.wordlist
    output_file = args.output_file

    if w_list:
        w_list = w_list[0]

    # check args
    if domain:
        if w_list:
            list = open(w_list, "r")
        else:
            list = open("list.txt", "r")
    else:
        write('error arguments: use cybercrowl -h to help')
        return

    # read
    data = read(domain, result)

    if isinstance(data, dict):
        url = None
        result = data
    else:
        url = data

    # try:

    # After check, start scan
    if url:
        result = crowl(list, url, args, result)
    # except TypeError:  # if Nonetype
    #     pass

    # close
    list.close()

    json_data = json.dumps(result)
    output_file.write_text(json_data)
    print(f"Final results save to {output_file.absolute().as_uri()}")


if __name__ == '__main__':
    main()
