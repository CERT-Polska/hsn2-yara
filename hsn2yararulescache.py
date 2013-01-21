#!/usr/bin/python -tt

# Copyright (c) NASK
# 
# This file is part of HoneySpider Network 2.0.
# 
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
Created on 2012-07-20

@author: pawelch
'''
import weakref
import yara
import logging

class YaraRules():
	'''
	A wrapper for Yara rules object. Required because weakref can't create weak reference
	for Yara rules object directly.
	'''
	def __init__(self, source):
		self._rules = yara.compile(source=source)

	def __call__(self):
		return self._rules

class YaraRulesCache():
	def __init__(self):
		logging.debug("Created YaraRulesCache object.")
		self.cache = weakref.WeakValueDictionary()

	def _getRules(self, source):
		key = id(source)
		rules = None

		if not self.cache.has_key(key):
			logging.debug("No key %d for rule set" % key)
			rules = YaraRules(source)
			self.cache[key] = rules

		if self.cache[key] is None:
			logging.debug("Rules from key %d are set to None" % key)
			rules = YaraRules(source)
			self.cache[key] = rules

		return self.cache[key]

	def getFileRules(self, filepath):
		# TODO: consider exchanging some responsibility with YaraRules
		with open(filepath, 'r') as f:
			source = f.read()
		return self._getRules(source)

	def getSourceRules(self, source):
		# TODO: consider exchanging some responsibility with YaraRules
		return self._getRules(source)

_yara_rules_cache_object = None

def getYaraRulesCache():
	global _yara_rules_cache_object
	if _yara_rules_cache_object is None:
		_yara_rules_cache_object = YaraRulesCache()
	return _yara_rules_cache_object
