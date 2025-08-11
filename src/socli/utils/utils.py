import functools
import asyncio
import inspect
from collections import OrderedDict
from collections.abc import Coroutine
from typing import Any, Callable, TypeVar, ParamSpec, overload

from loguru import logger

P = ParamSpec("P")
T = TypeVar("T")


def run_async(func: Callable[P, Coroutine[Any, Any, T]]) -> Callable[P, T]:
    """Decorator to run an async function in synchronous context."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        return asyncio.run(func(*args, **kwargs))

    return wrapper


@overload
def logit(
    func: Callable[P, Coroutine[Any, Any, T]],
) -> Callable[P, Coroutine[Any, Any, T]]: ...


@overload
def logit(func: Callable[P, T]) -> Callable[P, T]: ...


def logit(func: Callable[P, Any]) -> Callable[P, Any]:
    """Decorator to log function calls for both sync and async functions."""

    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            logger.info(f"Calling {func.__name__} with args: {args}, kwargs: {kwargs}")
            result = await func(*args, **kwargs)
            return result

        return async_wrapper
    else:

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            logger.info(f"Calling {func.__name__} with args: {args}, kwargs: {kwargs}")
            result = func(*args, **kwargs)
            return result

        return sync_wrapper


def async_lru_cache(
    maxsize: int | None = 128,
) -> Callable[
    [Callable[P, Coroutine[Any, Any, T]]], Callable[P, Coroutine[Any, Any, T]]
]:
    """LRU cache decorator for async functions (FIFO)."""

    def decorator(
        func: Callable[P, Coroutine[Any, Any, T]],
    ) -> Callable[P, Coroutine[Any, Any, T]]:
        cache: OrderedDict[tuple[Any, ...], T] = OrderedDict()

        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            key = (args, tuple(sorted(kwargs.items())))

            if key in cache:
                cache.move_to_end(key)
                return cache[key]

            result = await func(*args, **kwargs)

            cache[key] = result

            if maxsize is not None and len(cache) > maxsize:
                _ = cache.popitem(last=False)

            return result

        def cache_clear() -> None:
            """Clear the cache."""
            cache.clear()

        def cache_info() -> dict[str, int]:
            """Return cache statistics."""
            return {"size": len(cache), "maxsize": maxsize or -1}

        setattr(wrapper, "cache_clear", cache_clear)
        setattr(wrapper, "cache_info", cache_info)

        return wrapper

    return decorator
