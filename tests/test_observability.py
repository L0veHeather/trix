"""Tests for observability infrastructure.

验证可观测性增强：
- 任务状态日志 ([TaskState])
- 并发状态快照
- 并发安全性
"""

import json
import logging
import pytest
import time
import threading

from trix.core.scan_controller import ScanController
from trix.core.scan_phase import ScanPhase, ScanTask


class TestTaskStateLogging:
    """验证任务状态日志."""
    
    def test_start_task_logs_state(self, caplog):
        """start_task 应输出结构化日志."""
        with caplog.at_level(logging.INFO):
            controller = ScanController("http://example.com")
            task = ScanTask(
                url="http://example.com/test",
                method="GET",
                phase=ScanPhase.ENUMERATION,
                source="test"
            )
            
            controller.start_task(task)
        
        assert "[TaskState]" in caplog.text
        assert "state=STARTED" in caplog.text
        assert task.task_id in caplog.text

    def test_finish_task_logs_duration(self, caplog):
        """finish_task 应输出持续时间."""
        with caplog.at_level(logging.INFO):
            controller = ScanController("http://example.com")
            task = ScanTask(
                url="http://example.com/test",
                method="GET",
                phase=ScanPhase.ENUMERATION,
                source="test"
            )
            
            controller.start_task(task)
            time.sleep(0.01)  # 确保有可测量的持续时间
            controller.finish_task(task)
        
        assert "state=FINISHED" in caplog.text
        assert "duration_ms=" in caplog.text


class TestStateSnapshot:
    """验证状态快照."""
    
    def test_snapshot_is_serializable(self):
        """快照应可JSON序列化."""
        controller = ScanController("http://example.com")
        
        snapshot = controller.get_state_snapshot()
        
        # 不抛异常即通过
        serialized = json.dumps(snapshot)
        assert serialized is not None

    def test_snapshot_contains_required_fields(self):
        """快照应包含所有必需字段."""
        controller = ScanController("http://example.com")
        
        snapshot = controller.get_state_snapshot()
        
        required_fields = [
            "timestamp",
            "current_phase",
            "task_queue_size",
            "active_tasks",
            "completed_tasks_count",
            "discovered_urls_count",
            "discovered_params_count",
            "vulnerabilities_count",
            "suspected_vulnerabilities_count",
        ]
        for field in required_fields:
            assert field in snapshot, f"Missing field: {field}"

    def test_snapshot_active_tasks_has_age(self):
        """活动任务应包含年龄信息."""
        controller = ScanController("http://example.com")
        task = ScanTask(
            url="http://example.com/test",
            method="GET",
            phase=ScanPhase.ENUMERATION,
            source="test"
        )
        
        controller.start_task(task)
        time.sleep(0.1)
        snapshot = controller.get_state_snapshot()
        
        assert task.task_id in snapshot["active_tasks"]
        task_info = snapshot["active_tasks"][task.task_id]
        assert "start_time" in task_info
        assert "age_s" in task_info


class TestConcurrencySafety:
    """验证并发安全性."""
    
    def test_concurrent_task_operations(self):
        """并发操作应不引发竞态条件."""
        controller = ScanController("http://example.com")
        errors = []
        
        def worker(thread_id: int):
            try:
                for i in range(50):
                    task = ScanTask(
                        url=f"http://example.com/thread{thread_id}/task{i}",
                        method="GET",
                        phase=ScanPhase.ENUMERATION,
                        source="test"
                    )
                    controller.add_task(task)
                    controller.start_task(task)
                    controller.finish_task(task)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Concurrency errors: {errors}"

    def test_concurrent_snapshot_reads(self):
        """并发读取快照应不引发竞态条件."""
        controller = ScanController("http://example.com")
        snapshots = []
        errors = []
        
        def reader():
            try:
                for _ in range(100):
                    snapshot = controller.get_state_snapshot()
                    snapshots.append(snapshot)
            except Exception as e:
                errors.append(e)
        
        def writer():
            try:
                for i in range(100):
                    task = ScanTask(
                        url=f"http://example.com/writer/{i}",
                        method="GET",
                        phase=ScanPhase.ENUMERATION,
                        source="test"
                    )
                    controller.add_task(task)
            except Exception as e:
                errors.append(e)
        
        # 同时启动读写线程
        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Concurrency errors: {errors}"
        assert len(snapshots) > 0


class TestStuckTaskDetection:
    """验证卡死任务检测."""
    
    def test_active_tasks_age_increases(self):
        """活动任务的年龄应随时间增加."""
        controller = ScanController("http://example.com")
        task = ScanTask(
            url="http://example.com/test",
            method="GET",
            phase=ScanPhase.ENUMERATION,
            source="test"
        )
        
        controller.start_task(task)
        
        snapshot1 = controller.get_state_snapshot()
        time.sleep(0.5)
        snapshot2 = controller.get_state_snapshot()
        
        age1 = snapshot1["active_tasks"][task.task_id]["age_s"]
        age2 = snapshot2["active_tasks"][task.task_id]["age_s"]
        
        # 年龄应增加或保持（取决于时间精度）
        assert age2 >= age1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
