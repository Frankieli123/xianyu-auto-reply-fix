#!/usr/bin/env python3
"""
基于文件监控的日志收集器
"""

import os
import re
import glob
import time
import threading
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

class FileLogCollector:
    """基于文件监控的日志收集器"""
    
    def __init__(self, max_logs: int = 2000):
        self.max_logs = max_logs
        self.logs = deque(maxlen=max_logs)
        self.lock = threading.Lock()
        
        # 日志文件路径
        self.log_file = None
        self.last_position = 0
        
        # 启动文件监控
        self.setup_file_monitoring()
    
    def setup_file_monitoring(self):
        """设置文件监控"""
        self.cleanup_legacy_realtime_logs()

        # 实时日志固定写入 logs 目录，避免 /app 根目录文件在部分挂载环境下轮转失败
        self.log_file = str(Path("logs") / "realtime.log")
            
        # 设置loguru输出到文件
        self.setup_loguru_file_output()
        
        # 启动文件监控线程
        self.monitor_thread = threading.Thread(target=self.monitor_file, daemon=True)
        self.monitor_thread.start()
    
    def setup_loguru_file_output(self):
        """设置loguru输出到文件"""
        try:
            from loguru import logger
            
            # 确保logs目录存在
            logs_dir = Path("logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            
            # 添加实时日志文件输出（用于Web界面实时监控）
            logger.add(
                self.log_file,
                format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {name}:{function}:{line} - {message}",
                level="INFO",
                # 这一路日志只用于实时监控，不做 loguru 轮转，避免 rename 在部分挂载环境报 Errno 16
                enqueue=True,
                buffering=1,
                encoding="utf-8"
            )
            
            # 添加按日期轮转的日志文件输出到logs目录
            logger.add(
                "logs/xianyu_{time:YYYY-MM-DD}.log",
                format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
                level="INFO",
                rotation="00:00",  # 每天午夜轮转
                retention="7 days",  # 保留7天
                compression="zip",  # 压缩旧日志
                enqueue=False,
                buffering=1,
                encoding="utf-8"
            )
            
            logger.info("文件日志收集器已启动（实时日志 + 按日期轮转日志）")
            
        except ImportError:
            pass

    def cleanup_legacy_realtime_logs(self):
        """启动时清理旧版 realtime 日志文件（/app 根目录）。"""
        try:
            try:
                from loguru import logger as loguru_logger
            except Exception:
                loguru_logger = None

            root_candidates = {Path.cwd(), Path("/app")}
            removed_count = 0
            current_realtime_log = (Path("logs") / "realtime.log").resolve()

            for root in root_candidates:
                if not root.exists():
                    continue

                patterns = [
                    str(root / "realtime.log"),
                    str(root / "realtime.*.log"),
                ]

                for pattern in patterns:
                    for path in glob.glob(pattern):
                        try:
                            file_path = Path(path)
                            # 跳过当前新版实时日志路径（logs/realtime.log）
                            if file_path.resolve() == current_realtime_log:
                                continue
                            if file_path.is_file():
                                file_path.unlink(missing_ok=True)
                                removed_count += 1
                                if loguru_logger is not None:
                                    loguru_logger.debug(f"启动清理旧版realtime日志: 已删除 {file_path}")
                        except Exception:
                            continue

            if removed_count > 0 and loguru_logger is not None:
                loguru_logger.info(f"启动清理旧版realtime日志完成: 删除 {removed_count} 个文件")
        except Exception:
            pass
    
    def monitor_file(self):
        """监控日志文件变化"""
        while True:
            try:
                if os.path.exists(self.log_file):
                    # 获取文件大小
                    file_size = os.path.getsize(self.log_file)
                    if file_size < self.last_position:
                        # 文件被外部截断/重建后，从头继续读取
                        self.last_position = 0
                    
                    if file_size > self.last_position:
                        # 读取新增内容
                        with open(self.log_file, 'r', encoding='utf-8') as f:
                            f.seek(self.last_position)
                            new_lines = f.readlines()
                            self.last_position = f.tell()
                        
                        # 解析新增的日志行
                        for line in new_lines:
                            self.parse_log_line(line.strip())
                
                time.sleep(0.5)  # 每0.5秒检查一次
                
            except Exception as e:
                time.sleep(1)  # 出错时等待1秒
    
    def parse_log_line(self, line: str):
        """解析日志行"""
        if not line:
            return
        
        try:
            # 解析loguru格式的日志
            # 格式: 2025-07-23 15:46:03.430 | INFO | __main__:debug_collector:70 - 消息
            pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \| (\w+) \| ([^:]+):([^:]+):(\d+) - (.*)'
            match = re.match(pattern, line)
            
            if match:
                timestamp_str, level, source, function, line_num, message = match.groups()
                
                # 转换时间格式
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                except:
                    timestamp = datetime.now()
                
                log_entry = {
                    "timestamp": timestamp.isoformat(),
                    "level": level,
                    "source": source,
                    "function": function,
                    "line": int(line_num),
                    "message": message
                }
                
                with self.lock:
                    self.logs.append(log_entry)
            
        except Exception as e:
            # 如果解析失败，作为普通消息处理
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "level": "INFO",
                "source": "system",
                "function": "unknown",
                "line": 0,
                "message": line
            }
            
            with self.lock:
                self.logs.append(log_entry)
    
    def get_logs(self, lines: int = 200, level_filter: str = None, source_filter: str = None) -> List[Dict]:
        """获取日志记录"""
        with self.lock:
            logs_list = list(self.logs)
        
        # 应用过滤器
        if level_filter:
            logs_list = [log for log in logs_list if log['level'] == level_filter]
        
        if source_filter:
            logs_list = [log for log in logs_list if source_filter.lower() in log['source'].lower()]
        
        # 返回最后N行
        return logs_list[-lines:] if len(logs_list) > lines else logs_list
    
    def clear_logs(self):
        """清空日志"""
        with self.lock:
            self.logs.clear()
    
    def get_stats(self) -> Dict:
        """获取日志统计信息"""
        with self.lock:
            total_logs = len(self.logs)
            
            # 统计各级别日志数量
            level_counts = {}
            source_counts = {}
            
            for log in self.logs:
                level = log['level']
                source = log['source']
                
                level_counts[level] = level_counts.get(level, 0) + 1
                source_counts[source] = source_counts.get(source, 0) + 1
            
            return {
                "total_logs": total_logs,
                "level_counts": level_counts,
                "source_counts": source_counts,
                "max_capacity": self.max_logs,
                "log_file": self.log_file
            }


# 全局文件日志收集器实例
_file_collector = None
_file_collector_lock = threading.Lock()


def get_file_log_collector() -> FileLogCollector:
    """获取全局文件日志收集器实例"""
    global _file_collector
    
    if _file_collector is None:
        with _file_collector_lock:
            if _file_collector is None:
                _file_collector = FileLogCollector(max_logs=2000)
    
    return _file_collector


def setup_file_logging():
    """设置文件日志系统"""
    collector = get_file_log_collector()
    return collector


if __name__ == "__main__":
    # 测试文件日志收集器
    collector = setup_file_logging()
    
    # 生成一些测试日志
    from loguru import logger
    
    logger.info("文件日志收集器测试开始")
    logger.debug("这是调试信息")
    logger.warning("这是警告信息")
    logger.error("这是错误信息")
    logger.info("文件日志收集器测试结束")
    
    # 等待文件写入和监控
    time.sleep(2)
    
    # 获取日志
    logs = collector.get_logs(10)
    print(f"收集到 {len(logs)} 条日志:")
    for log in logs:
        print(f"  [{log['level']}] {log['source']}: {log['message']}")
    
    # 获取统计信息
    stats = collector.get_stats()
    print(f"\n统计信息: {stats}")
