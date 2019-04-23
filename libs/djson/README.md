Copyright (c) 2019 Diamond Key Security, NFP
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 2
of the License only.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
-----------------------------------------------------------------

Diamond-JSON is a simple JSON parser. It is used to facilitate parsing
a JSON string in order. Diamond-JSON uses a destructive process in that
it will add null terminators throught the original json string to mark
the end of strings. This allows the parser to work without allocating
any new memory.


