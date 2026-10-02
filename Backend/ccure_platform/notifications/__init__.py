"""
ccure_platform/notifications — in-app notifications as a platform capability.

``service.py`` creates, stores and publishes them (every module raises
notifications through it); ``router.py`` is the ``/notifications`` API the
platform shell's bell and panel use. The ``notifications`` table is the
platform's.

The type and category vocabularies still carry Audit's words (``scan_completed``,
``vulnerability_found``, the ``scan`` category). They moved as-is: a
cross-product category design is a later decision, recorded as a follow-up.
"""
