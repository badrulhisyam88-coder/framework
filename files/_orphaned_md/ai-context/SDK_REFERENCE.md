# SDK Reference

## Implemented

### Logging

```python
Logger.info(message, **context)
Logger.error(message, **context)
```

### Config

```python
Config.get(key, default=None)
```

---

## Planned (not yet implemented)

The interfaces below are documented as architectural targets.
They do not exist in sdk/ yet and will raise AttributeError if called.

### Queue

```python
Queue.publish(queue, payload)
```

### AI

```python
AIProvider.generate(prompt)
```

### Notifications

```python
Notification.send(message)
```

### Scheduler

```python
Scheduler.register(task)
```
