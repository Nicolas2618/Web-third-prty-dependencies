#region Imports
import dns.resolver
import dns.query
import dns.zone
import tldextract
import subprocess
import ssl
import socket
import json
import csv
import re
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
#endregion

#region Dataclass
@dataclass
class CDNResult:
    website: str
    cdns: list[str] = field(default_factory=list)
    cdn_types: dict[str, str] = field(default_factory=dict)
    uses_third_party: bool = False
    critical_dependency: bool = False
    redundant: bool = False
#endregion

#region Basic Helpers

#endregion

#region CDN Helpers

#endregion

#re