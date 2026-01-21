# i18n.py - 国际化支持模块
import json
import os
import sys

class I18n:
    """多语言支持类
    
    用法:
        i18n = I18n()
        i18n.set_language('zh_CN')
        text = i18n.t('menu.file')
    """
    
    def __init__(self, translations_file='translations.json', default_lang='zh_CN'):
        """初始化多语言支持
        
        Args:
            translations_file: 翻译文件路径
            default_lang: 默认语言代码
        """
        self.translations = {}
        self.current_lang = default_lang
        self.translations_file = translations_file
        self.callbacks = []  # 语言切换时的回调函数列表
        
        self._load_translations()

    def _get_resource_path(self, relative_path):
        """获取资源文件实际路径，兼容 PyInstaller 打包后路径"""
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)
    
    def _load_translations(self):
        """从JSON文件加载翻译数据"""
        try:
            translations_path = self._get_resource_path(self.translations_file)
            if os.path.exists(translations_path):
                with open(translations_path, 'r', encoding='utf-8') as f:
                    self.translations = json.load(f)
            else:
                print(f"Warning: Translation file not found: {translations_path}")
                self.translations = {}
        except Exception as e:
            print(f"Error loading translations: {e}")
            self.translations = {}
    
    def set_language(self, lang_code):
        """切换语言
        
        Args:
            lang_code: 语言代码，如 'zh_CN', 'en_US'
        """
        if lang_code in self.translations:
            self.current_lang = lang_code
            # 触发所有注册的回调函数
            for callback in self.callbacks:
                try:
                    callback()
                except Exception as e:
                    print(f"Error in language change callback: {e}")
        else:
            print(f"Warning: Language '{lang_code}' not found in translations")
    
    def get_current_language(self):
        """获取当前语言代码"""
        return self.current_lang
    
    def get_available_languages(self):
        """获取所有可用的语言列表
        
        Returns:
            字典，格式: {'zh_CN': '简体中文', 'en_US': 'English'}
        """
        return {
            'zh_CN': '简体中文',
            'en_US': 'English'
        }
    
    def register_callback(self, callback):
        """注册语言切换回调函数
        
        Args:
            callback: 无参数的回调函数
        """
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback):
        """注销语言切换回调函数"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def t(self, key, default=None):
        """翻译文本
        
        Args:
            key: 翻译键，支持点号分隔的嵌套键，如 'menu.file'
            default: 如果找不到翻译时返回的默认值
        
        Returns:
            翻译后的文本
        """
        if self.current_lang not in self.translations:
            return default or key
        
        # 支持嵌套键，如 'menu.file'
        keys = key.split('.')
        value = self.translations[self.current_lang]
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default or key
    
    def format(self, key, **kwargs):
        """翻译文本并格式化
        
        Args:
            key: 翻译键
            **kwargs: 格式化参数
        
        Returns:
            格式化后的文本
        
        Example:
            i18n.format('messages.hello', name='张三')
        """
        text = self.t(key)
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text


# 全局单例
_i18n_instance = None

def get_i18n():
    """获取全局 I18n 实例"""
    global _i18n_instance
    if _i18n_instance is None:
        _i18n_instance = I18n()
    return _i18n_instance

