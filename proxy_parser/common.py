from urllib import request
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from http.client import HTTPResponse
from html.parser import HTMLParser
from typing import List, Tuple, Dict, Union
from datetime import datetime, timedelta
from enum import Enum, unique
import socket
import pickle
import hashlib
import os
import csv
import json
import asyncio

__all__ = ['Proxy', 'ProxyList']

@unique
class ProxyTpe(Enum):
    HTTP = 'http'
    HTTPS = 'https'
    SOCKS4 = 'socks4'
    SOCKS5 = 'socks5'

    @classmethod
    def find(cls, value: str):
        for k, item in cls.__dict__.items():
            if isinstance(item, ProxyTpe) and item.value == value.lower():
                return item
        
        return None

    def __str__(self):
        return self.value


class CacheManager():
    def __init__(self, storage_path: str = './'):
        self.storage_path = storage_path

    def __get_cache_file(self, key: str):
        return os.path.join(self.storage_path, f'{key}.pickle')

    def save(self, data, key: str, time_diff: timedelta):
        """Сохраняем кеш"""
        cached_data: dict = {
            'data': data,
            'key': key,
            'time_exp': datetime.now() + time_diff
        }

        file_path: str = self.__get_cache_file(key)
        dir_name: str = os.path.dirname(file_path)
        if not os.path.isdir(dir_name):
            os.makedirs(dir_name, exist_ok=True)

        with open(file_path, 'wb') as f:
            pickle.dump(cached_data, f)

    def get(self, key: str):
        """Запрашиваем данные по ключу"""
        data = None
        if not self.check(key): 
            return None

        file_path: str = self.__get_cache_file(key)
        with open(file_path, 'rb') as f:
            cached_data: dict = pickle.load(f)
            data = cached_data.get('data', None)
        
        return data

    def check(self, key: str) -> bool:
        """Проверяем наличие актуального кеша"""
        is_success: bool = False
        file_path: str = self.__get_cache_file(key)
        if not os.path.isfile(file_path): 
            return False

        with open(file_path, 'rb') as f:
            cached_data: dict = pickle.load(f)
            time_exp = cached_data.get('time_exp', None)
            if time_exp is not None and time_exp >= datetime.now():
                is_success = True
            else:
                os.remove(file_path)

        return is_success

class HttpRequestResult():
    def __init__(
            self, 
            responce = None, 
            error: Exception = None, 
            body: str = None, 
            status: int = None, 
            headers = None):
        self.responce: HTTPResponse = responce
        self.error = error
        self.__body: str = body
        self.__status: int = status
        self.__headers = headers

    def is_success(self):
        if not self.responce:
            return False

        return 200 >= self.__status < 300

    def has_error(self) -> bool:
        if self.error:
            return True

        return False

    @property
    def headers(self):
        return self.__headers


    def get_body(self, encoding: str = 'utf-8') -> str:
        if not self.__body:
            return ''

        return self.__body.decode(encoding)

class HttpClient():
    headers: Dict[str, str] = {
        'Accept-Encoding': '',
        'Accept': 'gzip, deflate',
        'Accept-Language': 'ru',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'DNT': '1',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0',
    }

    def __init__(self, cache_time_diff: timedelta = None, cache_storage_dir: str = './'):
        self.cache_manager: CacheManager = CacheManager(cache_storage_dir)
        self.cache_time_diff = cache_time_diff

    def _prepare_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        result = self.headers
        for key, value in headers.items():
            result[key] = value

        return result

    def __internal_http_request(self, req: request.Request, cache_key: str, timeout: float = None):
        if not timeout:
            timeout = socket._GLOBAL_DEFAULT_TIMEOUT
        with request.urlopen(req, timeout=timeout) as resp:
            resp: HTTPResponse = request.urlopen(req)
            body: str = resp.read()
            resp.close()
            
            data: HttpRequestResult = HttpRequestResult(
                    responce=resp, 
                    status=resp.status, 
                    body=body, 
                    headers=resp.headers.items())

            return self._save_cache(cache_key, data)
            
        return None

    def _get_cache_key(self, url: str, method: str, data = None, headers: Dict[str, str] = {}) -> str:
        return hashlib.md5(pickle.dumps({
            'url': url,
            'method': method,
            'data': data,
            'headers': headers
        })).hexdigest()

    def _get_cache(self, cache_key: str) -> HttpRequestResult:
        if self.cache_time_diff is not None and self.cache_manager.check(cache_key):
            return self.cache_manager.get(cache_key)
        
        return None

    def _save_cache(self, cache_key: str, result: HttpRequestResult) -> HttpRequestResult:
        if self.cache_time_diff is not None:
                self.cache_manager.save(result, cache_key, self.cache_time_diff)
        return result

    def http_request(self, url: str, method: str, data = None, headers: Dict[str, str] = {}, timeout: float = None) -> HttpRequestResult:
        """HTTP запрос"""
        cache_key = self._get_cache_key(url, method, data, headers)
        if data:
            data = urlencode(data).encode('ascii')

        cache_result: HttpRequestResult = self._get_cache(cache_key)
        if cache_result is not None:
            return cache_result
        
        headers = self._prepare_headers(headers)
        req: request.Request = request.Request(url, headers=headers, data=data, method=method)
        request_result: HttpRequestResult = None

        try:
            request_result = self.__internal_http_request(req, cache_key)
        except (HTTPError, URLError) as request_error:
            request_result = HttpRequestResult(error=request_error)
        
        return request_result

    def http_get_request(self, url: str, headers: Dict[str, str] = {}, timeout: float = None) -> HttpRequestResult:
        """HTTP GET запрос"""
        return self.http_request(url, 'GET', None, headers, timeout)

    def http_post_request(self, url: str, data = None, headers: Dict[str, str] = {}, timeout: float = None) -> HttpRequestResult:
        """HTTP POST запрос"""
        return self.http_request(url, 'POST', data, headers, timeout)

    def http_put_request(self, url: str, data = None, headers: Dict[str, str] = {}, timeout: float = None) -> HttpRequestResult:
        """HTTP PUT запрос"""
        return self.http_request(url, 'PUT', data, headers, timeout)

    def http_delete_request(self, url: str, data = None, headers: Dict[str, str] = {}, timeout: float = None) -> HttpRequestResult:
        """HTTP DELETE запрос"""
        return self.http_request(url, 'DELETE', data, headers, timeout)

class Proxy(HttpClient):
    fields: List[str] = [
        'type',
        'addr',
        'port',
        'login',
        'password',
        'time_add',
        'time_check'
    ]

    def __init__(self, 
            proxy_type: ProxyTpe, 
            addr: str, 
            port: int, 
            login: str = None, 
            password: str = None,
            time_add: datetime = datetime.now(),
            time_check: datetime = None,
            **kwargs):
        self.type: ProxyTpe = proxy_type
        self.addr: str = addr
        self.port: int = port
        self.latency: float = 0
        self.login = login
        self.password = password
        self.__checked_latency: float = 0
        self.__time_add: datetime = time_add 
        self.__time_check: datetime = time_check
        self.__time_use: datetime = None

    def __str__(self) -> str:
        credential_str: str = ''
        if self.login is not None and self.password is not None:
            credential_str: str = '%s:%s@' % (self.login, self.password)
        elif self.login is not None:
            credential_str: str = '%s@' % self.login

        return '%s://%s%s:%s' % (self.type.value, credential_str, self.addr, self.port)

    def get_host(self) -> str:
        return '%s:%s' % (self.addr, self.port)

    @property
    def time_add(self) -> datetime:
        return self.__time_add

    @property
    def time_check(self) -> datetime:
        """Время проверки прокси-сервера"""
        return self.__time_ckeck

    async def check(self, timeout_sec: float = 1):
        """Проверка соединения с прокси-сервером"""
        try:
            self.__time_check = datetime.now()
            conn = asyncio.open_connection(self.addr, self.port)
            await asyncio.wait_for(conn, timeout=timeout_sec)
            conn.close()
            self.__checked_latency = timeout_sec
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            self.__checked_latency = 0


    @staticmethod
    def from_dict(data: dict):
        proxy_type_str = data.get('type', '')
        proxy_type: ProxyTpe = ProxyTpe.find(proxy_type_str)
        addr: str = data.get('addr', '')
        port: int = int(data.get('port', 0))
        login: str = data.get('login', None)
        password: str = data.get('password', None)

        return Proxy(proxy_type, addr, port, login=login, password=password)

    def to_dict(self) -> dict:
        return {
            'type': str(self.type),
            'addr': self.addr,
            'port': self.port,
            'login': self.login,
            'password': self.password,
            'time_add': self.__time_add,
            'time_check': self.__time_check
        }

    def in_timeout(self, timeout: float = 1) -> bool:
        return self.__checked_latency > 0 and self.__checked_latency <= timeout
        
class ProxyList(list):
    mode: str = 'normal'

    def append(self, item): 
        if isinstance(item, Proxy):
            super().append(item)

    def __getitem__(self, item):
        if isinstance(item, slice):
            lst = super().__getitem__(item)
            return self.__class__(lst)
        else:
            return super().__getitem__(item)

    def filter(self, proxy_type: ProxyTpe = None, checked_timeout: int = 0):
        """Фильтрация прокси-серверов"""
        result: ProxyList = ProxyList()
        result.set_mode(self.mode)
        for proxy in self:
            if proxy_type is not None and proxy.type != proxy_type:
                continue
            if checked_timeout > 0 and not proxy.in_timeout(checked_timeout):
                continue
            
            result.append(proxy)

        return result
    
    def set_mode(self, mode: str):
        """Режим перебора прокси-серверов"""
        self.mode: str = mode

    def sort(self, **kwargs):
        pass

    def __str__(self):
        return '\n'.join([str(proxy) for proxy in self])

    def load_csv(self, file_name: str):
        """Загрузка списка из csv"""
        with open(file_name, 'r') as f:
            csv_reader = csv.DictReader(f, fieldnames=Proxy.fields, delimiter=';')
            for item in csv_reader:
                self.append(Proxy.from_dict(item))

    def to_dict(self) -> List[dict]:
        """Конвертация в словарь"""
        return [item.to_dict() for item in self]

    def load_json(self, file_name: str):
        """Загрузка списка из json"""
        with open(file_name, 'r') as f:
            json_data: Dict = json.load(f)
            for item in json_data:
                self.append(Proxy.from_dict(item))

    def dump_csv(self, file_name: str):
        """Сохранение списка в csv"""
        with open(file_name, 'w') as f:
            csv_writer = csv.DictWriter(f, delimiter=';', fieldnames=Proxy.fields)
            for item in self.to_dict():
                csv_writer.writerow(item)

    def dump_json(self, file_name: str):
        """Сохранение списка в json"""
        with open(file_name, 'w') as f:
            json.dump(self.to_dict(), f)

    def check(self, timeout: float = 1):
        """Проверка соединения с прокси-серверами"""
        event_loop = asyncio.get_event_loop()
        task_list: list = []
        for proxy in self:
            task = event_loop.create_task(proxy.check(timeout))
            task_list.append(task)

        event_loop.run_until_complete(asyncio.wait(task_list))

        return self

class CommonProxyParser(HTMLParser):
    headers: Dict[str, str] = {}

    def __init__(self):
        self.http_client: HttpClient = HttpClient(cache_time_diff=timedelta(hours=1), cache_storage_dir='.cache/')
        self.proxy_list: ProxyList = ProxyList()
        self.addr = ''
        self.type = ''
        self.port = 0
        super().__init__()

    def get_html(self, url: str, encoding: str = 'utf-8') -> str:
        return self.http_client.http_get_request(url, headers=self.headers).get_body(encoding=encoding)

    def __str__(self):
        return str(self.proxy_list)