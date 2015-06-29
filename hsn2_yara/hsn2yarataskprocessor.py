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
Created on 2012-07-10

@author: pawelch
'''

from hsn2_commons.hsn2taskprocessor import HSN2TaskProcessor
from hsn2_commons.hsn2taskprocessor import ParamException
from hsn2_commons.hsn2osadapter import ObjectStoreException
from hsn2_commons import hsn2objectwrapper as ow
from hsn2_yara import hsn2yararulescache
import logging
import os
import time
import tempfile
import yara

class YaraTaskProcessor(HSN2TaskProcessor):

	matches = []

	def __init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra):
		HSN2TaskProcessor.__init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra)
		self.rules_cache = hsn2yararulescache.getYaraRulesCache()

	def taskProcess(self):
		'''
		Returns a list of warnings (warnings). The current task is available at self.currentTask
		'''
		logging.debug(self.__class__)
		logging.debug(self.currentTask)
		logging.debug(self.objects)
		if len(self.objects) == 0:
			raise ObjectStoreException("Task processing didn't find task object.")

		content = ""
		if self.objects[0].isSet("content"):
			content = self.dsAdapter.getFile(self.currentTask.job, self.objects[0].content.getKey())
		else:
			raise ParamException("content is missing.")

		rules = None
		for param in self.currentTask.parameters:
			if param.name == "rules_filename":
				value = str(param.value)
				if len(value) > 0:
					# TODO: try-except? what if file doesn't exist? what if ruleset is incorrect?
					rules = self.rules_cache.getFileRules(value)
				break
			if param.name == "rules_string":
				value = str(param.value)
				if len(value) > 0:
					# TODO: try-except? what if ruleset is incorrect?
					rules = self.rules_cache.getSourceRules(value)
		if rules is None:
			raise ParamException("Both rules_filename and rules_string are missing. One of them is required.")

		self.objects[0].addTime("yara_time_start",int(time.time() * 1000))
		matches = rules().match(data=content, callback=self.getYaraDetails)
		self.objects[0].addTime("yara_time_stop",int(time.time() * 1000))

		if len(matches) > 0:
			pblist = ow.toYaraMatchesList(self.matches)
			tmp = tempfile.mkstemp()
			os.write(tmp[0], pblist.SerializeToString())
			os.close(tmp[0])
			self.objects[0].addBool("yara_matches_found",True)
			self.objects[0].addBytes("yara_matches_list",self.dsAdapter.putFile(tmp[1],self.currentTask.job))
			os.remove(tmp[1])
		else:
			self.objects[0].addBool("yara_matches_found",False)

		return []

	def getYaraDetails(self, data):
		if (data['matches']):
			newmatch = {}
			newmatch['rule'] = data['rule']
			newmatch['namespace'] = data['namespace']
			self.matches.append(newmatch)
		yara.CALLBACK_CONTINUE
