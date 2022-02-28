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

#pragma once

#include <filter/parser.h>
#include <string>
#include <vector>
#include <set>
#include <map>

/*!
	\brief Helper class for substituting and resolving list
	refereces in parsed filters.
*/
class filter_list_resolver: private libsinsp::filter::ast::base_expr_visitor
{
	public:
		/*!
			\brief Visits a filter AST and substitutes list references
			according with all the definitions added through define_list().
			\param filter The filter AST to be processed. Note that the pointer is
			passed by reference, and can potentially change in order to apply
			the substutions. In that case, the old pointer is owned by this
			class and is deleted automatically.
		*/
		void process(libsinsp::filter::ast::expr*& filter);

		/*!
			\brief Defines a new list to be substituted in filters. If called
			multiple times for the same list name, the previous definition
			gets overridden.
			\param name The name of the list.
			\param values The values contained in the list.
		*/
		void define_list(std::string name, std::vector<std::string>& values); 

		/*!
			\brief Returns a set containing the names of all the lists
			substituted during the last invocation of process().
		*/
		std::set<std::string>& get_resolved_lists();
		
	private:
		void visit(libsinsp::filter::ast::list_expr& e) override;

		std::set<std::string> m_resolved_lists;
		std::map<std::string, std::vector<std::string>> m_lists;
};
