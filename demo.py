#!/usr/bin/env python
#*******************************************************************************
#*   Ledger Blue
#*   (c) 2016 Ledger
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
from ledgerblue.comm import getDongle
dongle = getDongle(True)
dongle.exchange(bytes("80F2000000".decode('hex')))
dongle.exchange(bytes("80F2010000".decode('hex')))
dongle.exchange(bytes("80D10000148000002B8000003C8000062D8000000000000000".decode('hex')))
dongle.exchange(bytes("80F2010000".decode('hex')))
dongle.exchange(bytes("80C0000020e7885344700c16ffcb5c312946764cdc7047e5dbed2b854ba1d19aeeafae5aac".decode('hex')))
