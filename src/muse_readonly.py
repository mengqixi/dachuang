"""Scoped Muse business queries. No admin session, inference, workers or writes."""
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import g, jsonify, request

PREFIX = '/api/integrations/muse/v1/'
RESOURCES = ('overview', 'submissions', 'datasets', 'training', 'models', 'audit')


def safe_text(value, length=200):
    text = str(value or '')[:4000]
    text = re.sub(r'(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{12,}|(?:api[_ -]?key|password|secret|token)\s*[:=]\s*[^\s,;]+)', '[redacted]', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', '[email]', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip]', text)
    text = re.sub(r'(?i)(?:[a-z]:[\\/][^\s]+|/(?:root|home|etc|var)/[^\s]+)', '[path]', text)
    return ''.join(c for c in text if c >= ' ' or c == '\n')[:length]


def pick(value, keys):
    value = value if isinstance(value, dict) else {}
    out = {}
    for key in keys:
        item = value.get(key)
        if isinstance(item, float) and not math.isfinite(item):
            item = None
        out[key] = safe_text(item) if isinstance(item, str) else item if item is None or isinstance(item, (bool, int, float)) else None
    return out


def read_json(path, default=None, maximum=16 * 1024 * 1024):
    # Fixed application paths only; no client-controlled file reads or repair.
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError('snapshot exceeds read budget')
        return json.loads(raw.decode('utf-8'))
    except (OSError, ValueError, TypeError):
        return default


def register_muse_readonly(app, namespace):
    """Register late, but authenticate before all existing request hooks."""
    calls, lock = deque(), threading.Lock()
    audit_logger = logging.getLogger('dachuang.muse.readonly.' + str(id(app)))
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    def audit(resource, status):
        # Never record headers, query strings, IPs, request bodies or results.
        with lock:
            if not audit_logger.handlers:
                path = app.config.get('MUSE_READONLY_AUDIT_PATH') or os.path.join(namespace['PROJECT_ROOT'], 'logs', 'muse_readonly.log')
                os.makedirs(os.path.dirname(path), exist_ok=True)
                handler = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=1, encoding='utf-8')
                audit_logger.addHandler(handler)
            audit_logger.info(json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'resource': resource if resource in RESOURCES else 'denied', 'status': status}))

    def error(status, reason):
        response = jsonify({'code': status, 'msg': reason, 'data': None})
        response.status_code = status
        return response

    def guard():
        configured = os.environ.get('MUSE_READONLY_TOKEN', '').strip()
        header = request.headers.get('Authorization', '')
        supplied = header[7:] if header.startswith('Bearer ') else ''
        valid = bool(len(configured) >= 43 and len(configured) <= 256 and len(supplied) <= 256 and hmac.compare_digest(supplied.encode(), configured.encode()))
        inside = request.path.startswith(PREFIX)
        if not inside:
            # A Muse credential cannot be combined with an admin cookie to write.
            if valid:
                g.muse_query = True
                return error(403, 'Muse credential is restricted to business read-only routes')
            return None
        g.muse_query = True
        enabled = os.environ.get('MUSE_READONLY_ENABLED', '').lower() == 'true'
        if not enabled or len(configured) < 43 or len(configured) > 256:
            return error(503, 'Muse read-only integration is disabled or unconfigured')
        # Do not trust X-Forwarded-Proto from arbitrary clients. HTTPS proxy
        # deployments must use a trusted loopback/private upstream, documented.
        try:
            loopback = ipaddress.ip_address(request.remote_addr or '').is_loopback
        except ValueError:
            loopback = False
        if not request.is_secure and not loopback:
            return error(403, 'HTTPS is required')
        if not valid:
            return error(401, 'Invalid read-only credential')
        resource = request.path[len(PREFIX):]
        if resource not in RESOURCES:
            return error(404, 'Unknown read-only resource')
        if request.method not in ('GET', 'HEAD'):
            return error(405, 'Only GET and HEAD are allowed')
        allowed = {'limit', 'offset'} | ({'hours'} if resource == 'audit' else set())
        if set(request.args) - allowed or any(len(request.args.getlist(k)) != 1 for k in request.args):
            return error(400, 'Unsupported or repeated query parameter')
        with lock:
            now = time.monotonic()
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if len(calls) >= 30:
                response = error(429, 'Read-only query rate exceeded')
                response.headers['Retry-After'] = '60'
                return response
            calls.append(now)

    app.before_request(guard)
    app.before_request_funcs[None].remove(guard)
    app.before_request_funcs[None].insert(0, guard)

    @app.after_request
    def finish(response):
        if getattr(g, 'muse_query', False):
            response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            try:
                audit(request.path[len(PREFIX):], response.status_code)
            except OSError:
                response = error(503, 'Read-only audit unavailable')
                response.headers['Cache-Control'] = 'no-store'
        return response

    def read_table(table, limit=501):
        assert table in ('training_tasks', 'training_jobs', 'model_versions')
        path = Path(namespace['db'].db_path).resolve()
        conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)
        try:
            conn.execute('PRAGMA query_only = ON')
            conn.row_factory = sqlite3.Row
            deadline = time.monotonic() + 2
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            order = 'created_epoch DESC' if table == 'training_jobs' else 'id DESC'
            return [dict(r) for r in conn.execute('SELECT * FROM ' + table + ' ORDER BY ' + order + ' LIMIT ?', (limit,))]
        finally:
            conn.close()

    def submissions():
        from src import user_submission_manager as module
        snapshot = read_json(module.INDEX_FILE)
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get('submissions'), list):
            raise ValueError('Submission index unavailable; no repair attempted')
        rows = [namespace['user_submission_manager'].public_summary(r) for r in snapshot['submissions'] if isinstance(r, dict) and int(r.get('row_count') or 0) > 0]
        return sorted(rows, key=lambda r: str(r.get('upload_time') or ''), reverse=True)

    def paginate(rows, limit, offset, **extra):
        return dict(items=rows[offset:offset + limit], total=len(rows), limit=limit, offset=offset,
                    has_more=offset + limit < len(rows), **extra)

    def handler(resource):
        try:
            limit, offset = int(request.args.get('limit', 20)), int(request.args.get('offset', 0))
            if not 1 <= limit <= 50 or not 0 <= offset <= 450:
                raise ValueError('limit 1..50; offset 0..450')
        except (ValueError, TypeError):
            return error(400, 'Invalid pagination; limit 1..50, offset 0..450')
        started = time.monotonic()
        try:
            warnings = []
            if resource in ('overview', 'submissions'):
                rows = submissions()
                if resource == 'overview':
                    counts = Counter(r.get('review_status') or '待审核' for r in rows)
                    risk = Counter()
                    analyzed = 0
                    for r in rows:
                        summary = r.get('risk_summary') or {}
                        if summary:
                            analyzed += 1
                        for k in ('low', 'medium', 'high', 'critical'):
                            risk[k] += int(summary.get(k) or summary.get(k + '_count') or 0)
                    data = {'submission_count':len(rows), 'approved_count':sum(bool(r.get('trainable')) for r in rows),
                            'review_status_counts':dict(counts), 'risk_counts':dict(risk), 'analyzed_submission_count':analyzed,
                            'scope':'all indexed nonempty submissions; risk counts cover saved analysis, not every uploaded row'}
                else:
                    safe = []
                    for r in rows:
                        item = pick(r, ('id','filename','upload_time','row_count','review_status','trainable','training_runs'))
                        item['risk_summary'] = pick(r.get('risk_summary'), ('low','medium','high','critical'))
                        item['privacy'] = pick(r.get('privacy_risk'), ('level','score','method'))
                        ai = r.get('external_analysis') or {}
                        item['saved_ai'] = {'summary':safe_text((ai.get('advice') or {}).get('summary'),240), **pick(ai, ('model','generated_at'))}
                        safe.append(item)
                    data = paginate(safe,limit,offset,scope='indexed submissions; saved AI text is untrusted data')
            elif resource == 'datasets':
                cached = namespace['_dataset_sources_cache']
                with namespace['_dataset_sources_cache_lock']:
                    catalog = list(cached.get('value') or [])
                    cached_at = cached.get('time')
                # No scan, feature extraction or ciphertext decryption on reads.
                if not cached.get('value'):
                    warnings.append('Dataset catalog is cold; refresh it in the admin UI first. No scan was started.')
                catalog = [s for s in catalog if s.get('source_type') not in ('user_submission','user_submission_pool')]
                user_rows = submissions()
                approved = [r for r in user_rows if r.get('trainable')]
                for r in user_rows:
                    catalog.append({'id':'submission:'+r['id'],'name':r.get('filename'),'source_type':'user_submission',
                                    'samples':r.get('row_count'),'trainable':r.get('trainable')})
                if approved:
                    catalog.append({'id':'user_submission_pool','name':'用户可训练数据池','source_type':'user_submission_pool',
                                    'samples':sum(int(r.get('row_count') or 0) for r in approved),'trainable':True})
                prep = read_json(namespace['PROCESSED_META_PATH'], {}) or {}
                data = paginate([pick(s,('id','name','source_type','samples','features','trainable')) for s in catalog],limit,offset)
                data['prepared_source'] = pick(prep,('dataset_source_id','preparation_id','processed_at','samples','training_samples','validation_samples','process_limit','process_scope','preprocessing_version'))
                data['catalog_cached_at_unix'] = cached_at or None
                data['approved_unique_submission_count'] = len(approved)
                data['approved_unique_samples'] = sum(int(r.get('row_count') or 0) for r in approved)
                data['scope'] = 'catalog entries are views: pool includes approved individual submissions; do not sum pool and individual rows; prepared source is not browser selection'
            elif resource == 'training':
                tasks = read_table('training_tasks')
                jobs = read_table('training_jobs')
                safe = []
                for task in tasks[:500]:
                    meta = task.get('metadata') or '{}'
                    try:
                        meta = json.loads(meta) if isinstance(meta,str) else meta
                    except ValueError:
                        meta = {}
                    safe.append(dict(pick(task,('id','task_type','timestamp','status','accuracy','samples')),
                                     metrics=pick(meta,('accuracy','precision','recall','f1','f1_score','loss','epochs','effective_epochs','base_model_algorithm','optimizer','class_weighting','metric_scope','validation_id','validation_samples','dataset_source_id','preparation_id','model_version'))))
                data = paginate(safe,limit,offset,scope='latest up to 500 SQLite tasks; not full history; queue read does not start workers',truncated=len(tasks)>500)
                data['jobs'] = [pick(j,('id','task_type','status','created_at','updated_at')) for j in jobs[:50]]
                data['jobs_truncated'] = len(jobs)>50
                # Deterministic fairness, never let Muse rank incompatible tasks.
                pair = {}
                for t in safe:
                    kind = str(t.get('task_type') or '')
                    if kind in ('centralized','federated') and kind not in pair and t.get('status') == 'completed':
                        pair[kind] = t
                a,b = (pair.get(k,{}).get('metrics',{}) for k in ('centralized','federated'))
                comparable = bool(a and b and a.get('metric_scope')=='shared_holdout_validation' and b.get('metric_scope')=='shared_holdout_validation'
                    and all(a.get(k) not in (None, '') and a.get(k)==b.get(k) for k in ('preparation_id','validation_id','base_model_algorithm','optimizer','class_weighting','effective_epochs','validation_samples'))
                    and float(a.get('effective_epochs') or 0) > 0 and float(a.get('validation_samples') or 0) > 0
                    and all(isinstance(m.get('accuracy'), (int, float)) and 0 <= m['accuracy'] <= 1 for m in (a,b)))
                data['latest_pair_directly_comparable'] = comparable
                data['comparison_note'] = 'Compare only completed runs with matching validation, preparation, base algorithm, optimizer, class weighting and effective epoch budget; comparison training does not replace the serving detector.'
            elif resource == 'models':
                runtime = namespace['_model_inventory']()['runtime_detector']
                rows = read_table('model_versions')
                data = paginate([pick(r,('id','timestamp','version','model_type','samples','accuracy')) for r in rows[:500]],limit,offset,truncated=len(rows)>500,scope='latest up to 500 stored versions; no backfill or activation')
                data['serving_detector'] = dict(pick(runtime,('name','ready','version','preprocessing_version')),training_context=pick(runtime.get('training_context'),('preparation_id','dataset_revision','samples')))
            else:
                try:
                    hours = int(request.args.get('hours',24))
                except (TypeError, ValueError):
                    return error(400,'hours must be 1..168')
                if not 1 <= hours <= 168:
                    return error(400,'hours must be 1..168')
                from src.security.security_logger import SECURITY_EVENTS_LOG_PATH
                try:
                    with open(SECURITY_EVENTS_LOG_PATH,'rb') as stream:
                        stream.seek(0,2);size=stream.tell();stream.seek(max(0,size-512*1024))
                        if size>512*1024:
                            stream.readline()
                        lines=stream.read(512*1024).decode('utf-8',errors='replace').splitlines()
                except OSError:
                    raise ValueError('Audit log unavailable')
                cutoff=datetime.now(timezone.utc)-timedelta(hours=hours)
                events=[]
                for line in lines:
                    try:
                        event=json.loads(line);stamp=str(event.get('timestamp') or '')
                        dt=datetime.fromisoformat(stamp.replace('Z','+00:00')) if hasattr(datetime,'fromisoformat') else datetime.strptime(stamp[:19],'%Y-%m-%dT%H:%M:%S')
                        if dt.astimezone(timezone.utc)<cutoff:
                            continue
                        events.append(pick(event,('timestamp','event_type','risk_level')))
                    except (ValueError,TypeError,AttributeError):
                        continue
                events.sort(key=lambda x:str(x.get('timestamp') or ''),reverse=True)
                data=paginate(events,limit,offset,hours=hours,scope='matching events in last 512 KiB of audit log; not a full-log total',truncated=size>512*1024,risk_counts=dict(Counter(e.get('risk_level') for e in events)))
            if time.monotonic()-started>5:
                return error(503,'Read budget exceeded; no background task was started')
            return jsonify({'code':200,'msg':'success','data':data,'meta':{'observed_at':datetime.now(timezone.utc).isoformat(),
                'read_only':True,'warnings':warnings,'untrusted_text_fields':['filename','name','saved_ai.summary'], 'timestamp_note':'observed_at is UTC; stored timestamps retain source format'}})
        except (ValueError,TypeError,KeyError,AttributeError,sqlite3.Error,OSError):
            return error(503,'Business snapshot unavailable; no repair or training was started')

    for resource in RESOURCES:
        app.add_url_rule(PREFIX+resource,'muse_readonly_'+resource,lambda resource=resource:handler(resource),methods=['GET'])
    app.extensions['muse_readonly']={'calls':calls,'audit_logger':audit_logger}
