from common import CommonProxyParser, Proxy, ProxyList, ProxyTpe
from typing import List, Tuple, Dict
from enum import Enum, Flag, unique, auto
import base64
import json

@unique
class FreeProxyCzSort(Enum):
    PING = 'ping'
    SPEED = 'speed'
    UPTIME = 'uptime'
    DATE = 'date'

@unique
class FreeProxyCzType(Enum):
    HTTP = 'http'
    HTTPS = 'https'
    SOCKS = 'socks'
    SOCKS4 = 'socks4'
    SOCKS5 = 'socks5'
    ALL = 'all'

@unique
class FreeProxyCzLevel(Enum):
    LEVEL1 = 'level1'
    LEVEL2 = 'level2'
    LEVEL3 = 'level3'
    ALL = 'all'

class FreeProxyCzParser(CommonProxyParser):
    """Список прокси с сайта http://free-proxy.cz"""
    url: str = 'http://free-proxy.cz/en/proxylist/country/%s/%s/%s/%s/%s'
    
    def __init__(
            self, 
            pages: List[int], 
            sort: FreeProxyCzSort = FreeProxyCzSort.PING,
            protocol: FreeProxyCzType = FreeProxyCzType.ALL,
            level: FreeProxyCzLevel = FreeProxyCzLevel.ALL,
            country: str = 'all'):
        self.sort = sort.value
        self.level = level.value
        self.protocol = protocol.value
        self.country = country
        self.parse_table: bool = False
        self.parse_port: bool = False
        self.parse_type: bool = False
        self.new_proxy: bool = True

        super().__init__()
        self.headers['Host'] = 'free-proxy.cz'
        for page in pages:
            self.html = self.get_html_page(page)
            self.feed(self.html)

    def get_html_page(self, page: int) -> str:
        """Запрос страницы со списком прокси-серверов"""
        params: set = (self.country, self.protocol, self.sort, self.level, page)
        return self.get_html(self.url % params)

    def handle_starttag(self, tag, attrs):
        """Обработка открывающих тегов"""
        if tag == 'table' and ('id', 'proxy_list') in attrs: 
            self.parse_table = True

        if not self.parse_table:
            return

        if tag == 'span' and ('class', 'fport') in attrs:
            self.parse_port = True
        else:
            self.parse_port = False

        if tag == 'small':
            self.parse_type = True
        else:
            self.parse_type = False


    def handle_data(self, data: str):
        """Обработка данных (текст)"""
        if not self.parse_table:
            return

        if 'document.write(Base64.decode("' in data:
            enc_addr: str = data.replace('document.write(Base64.decode("', '').replace('"))', '').encode('ascii')
            self.addr = base64.decodebytes(enc_addr).decode('ascii')
            self.new_proxy = True

        if self.parse_port:
            self.port = int(data)

        if self.new_proxy and self.parse_type:
            proxy_type: ProxyTpe = ProxyTpe.find(data)
            self.proxy_list.append(Proxy(proxy_type, self.addr, self.port))
            self.new_proxy = False

class FreeProxyListNetParser(CommonProxyParser):
    url: str = 'https://free-proxy-list.net/'

    def __init__(self):
        self.parse_list: bool = False
        super().__init__()
        self.headers['Host'] = 'free-proxy-list.net'
        self.html = self.get_html(self.url)
        self.feed(self.html)

    def handle_starttag(self, tag, attrs):
        """Обработка открывающих тегов"""
        if tag == 'textarea' and ('class', 'form-control') in attrs \
                and ('readonly', 'readonly') in attrs and ('rows', '12') in attrs \
                and ('onclick', 'select(this)') in attrs: 
            self.parse_list = True

    def handle_data(self, data: str):
        """Обработка данных (текст)"""
        raw_list_header: str = 'Free proxies from free-proxy-list.net'
        if self.parse_list and raw_list_header in data:
            self.parse_list = False
            raw_list: str = data.replace(raw_list_header, '')
            proxy_list: List[str] = raw_list.split()
            for raw_proxy in proxy_list[5:]:
                addr, port = raw_proxy.split(':')
                proxy_type: ProxyType = ProxyTpe.find('http')
                self.proxy_list.append(Proxy(proxy_type, addr, int(port)))


class SpysOneParser(CommonProxyParser):
    url: str = 'http://spys.one/en/free-proxy-list/'

    def __init__(self):
        self.const_list: Dict[str, int] = {}
        self.current_addr: str = ''
        self.current_port: int = 0
        self.is_https: bool = False
        self.row_start: bool = False
        self.parse_addr: bool = False
        self.parse_port: bool = False
        self.parse_type: bool = False
        self.start_parse_constants: bool = False
        self.finish_parse_constants: bool = False
        super().__init__()
        self.headers['Host'] = 'free-proxy-list.net'
        self.html = self.get_html_page()
        self.feed(self.html)

    def get_html_page(self) -> str:
        """Запрос страницы со списком прокси-серверов"""
        post_data: Dict[str, int] = {
            'xpp': 5,
            'xf1': 0,
            'xf2': 0,
            'xf4': 0,
            'xf5': 0,
        }
        request_result: HttpRequestResult = self.http_client.http_post_request(self.url, data=post_data)

        return request_result.get_body()

    def handle_starttag(self, tag, attrs):
        """Обработка открывающих тегов"""
        if not self.finish_parse_constants and tag == 'script' and ('type', 'text/javascript') in attrs: 
            self.start_parse_constants = True

        if tag == 'tr' and ('class', 'spy1xx') in attrs:
            self.row_start = True

        if self.row_start and tag == 'font' and ('class', 'spy14') in attrs:
            self.parse_addr = True

        if self.row_start and tag == 'a' and ('href', '/en/https-ssl-proxy/') in attrs:
            self.is_https = True

        if self.row_start and tag == 'font' and ('class', 'spy1') in attrs:
            self.parse_type = True
            self.row_start = False

        if self.parse_addr and tag == 'script' and ('type', 'text/javascript') in attrs:
            self.parse_port = True

    def __parse_constants(self, data: str):
        """Парсинг констант для вычисления порта"""
        const_expression: List[str] = data.split(';')
        for raw_expr in const_expression:
            const_expr_list: List[str] = raw_expr.split('=')
            if len(const_expr_list) < 2:
                continue

            const_name, const_expr = const_expr_list
            expr_list: List[str] = const_expr.split('^')
            num: int = int(expr_list[0])
            if len(expr_list) > 1: 
                other_const_name: str = expr_list[1]
                other_const: int = self.const_list.get(other_const_name, 0)
                self.const_list[const_name] = num ^ other_const
            else: 
                self.const_list[const_name] = num

        self.start_parse_constants = False
        self.finish_parse_constants = True

    def __parse_port(self, data: str):
        """Парсинг порта"""
        data = data.replace('document.write("<font class=spy2>:<\/font>"+', '')
        expr_list = data.split('+')
        port_num_list: List[str] = []
        for raw_expr in expr_list:
            raw_expr = raw_expr.replace('(', '').replace(')', '')
            num_list = raw_expr.split('^')
            num1_name = num_list[0]
            num1 = self.const_list[num1_name]
            if len(num_list) > 1:
                num2_name = num_list[1]
                num2 = self.const_list[num2_name]
                port_num_list.append(str(num1^num2))
            else:
                port_num_list.append(str(num1))

        self.current_port = int(''.join(port_num_list))
        self.parse_addr = False
        self.parse_port = False

    def handle_data(self, data: str):
        """Обработка данных (текст)"""
        if self.start_parse_constants:
            self.__parse_constants(data)

        if not self.parse_port and self.parse_addr:
            self.current_addr = data

        if self.parse_port:
            self.__parse_port(data)

        if self.parse_type:
            if self.is_https:
                proxy_type: str = 'https'
            else:
                proxy_type: str = data.lower()

            proxy_type: ProxyType = ProxyTpe.find(proxy_type)
            self.proxy_list.append(Proxy(proxy_type, self.current_addr, self.current_port))
            self.parse_type = False
            self.is_https = False

class ProxyScrapeType(Flag):
    HTTP = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()
    ALL = HTTP|SOCKS4|SOCKS5

class ProxyScrapeParser(CommonProxyParser):
    url: str = 'https://api.proxyscrape.com/?request=getproxies&proxytype=%s&timeout=10000&country=all&ssl=all&anonymity=all'

    def __init__(self, protocol: ProxyScrapeType = ProxyScrapeType.ALL):
        super().__init__()
        for i, proxy_type in enumerate(['http', 'socks4', 'socks5']):
            current_protocol: int = (1<<i)
            if protocol.value & current_protocol != current_protocol:
                continue

            url = self.url % proxy_type
            request_result = self.http_client.http_get_request(url)
            if not request_result or not request_result.is_success():
                continue

            raw_proxy_list = request_result.get_body().split()
            for raw_proxy in raw_proxy_list:
                proxy_data = raw_proxy.split(':')
                if len(proxy_data) < 2: 
                    continue

                addr, str_port = proxy_data
                proxy_type: ProxyTpe = ProxyTpe.find(proxy_type)
                self.proxy_list.append(Proxy(proxy_type, addr, int(str_port)))

class ProxyListDownloadType(Flag):
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()
    ALL = HTTP|HTTPS|SOCKS4|SOCKS5

class ProxyListDownloadParser(CommonProxyParser):
    url: str = 'https://www.proxy-list.download/api/v0/get?l=en&t=%s'

    def __init__(self, protocol: ProxyListDownloadType = ProxyListDownloadType.ALL):
        self.parse_textarea_list: bool = False
        super().__init__()
        self.headers['Host'] = 'www.proxy-list.download'
        for i, proxy_type in enumerate(['http', 'https', 'socks4', 'socks5']):
            current_protocol: int = (1<<i)
            if protocol.value & current_protocol != current_protocol:
                continue

            url = self.url % proxy_type
            request_result = self.http_client.http_get_request(url)
            if not request_result.is_success():
                continue

            data = request_result.get_body()
            json_data = json.loads(data)
            json_proxy_list: List[Dict] = json_data[0].get('LISTA', [])
            proxy_type: ProxyTpe = ProxyTpe.find(proxy_type)
            for item in json_proxy_list:
                addr = item.get('IP', None)
                port_str = item.get('PORT', None)
                if not addr or not port_str:
                    continue

                self.proxy_list.append(Proxy(proxy_type, addr, int(port_str)))

print(ProxyListDownloadParser().proxy_list.filter(proxy_type=ProxyTpe.HTTP)[::-1])