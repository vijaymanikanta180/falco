/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "filter_list_resolver.h"

using namespace std;
using namespace libsinsp::filter;

void filter_list_resolver::run(libsinsp::filter::ast::expr*& filter)
{
	m_resolved_lists.clear();
	filter->accept(*this);
}

void filter_list_resolver::set_list(string name, std::vector<std::string>& values)
{
	m_lists[name] = values;
}

set<string>& filter_list_resolver::get_resolved_lists()
{
	return m_resolved_lists;
}

void filter_list_resolver::visit(ast::list_expr& e)
{
	bool resolved = false;
	vector<string> new_values;
	for (auto &v : e.values)
	{
		auto list = m_lists.find(v);
		if (list != m_lists.end())
		{   
			for (auto &subv : list->second)
			{
				new_values.push_back(subv);
			}
			resolved = true;
			m_resolved_lists.insert(v);
		}
		else
		{
			new_values.push_back(v);
		}
	}
	if (resolved)
	{
		e.values = new_values;
	}
}
