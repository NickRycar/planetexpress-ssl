# encoding: utf-8
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Dominik Richter
# author: Christoph Hartmann
# author: Alex Pop
# author: Patrick Münch
# author: Christoph Kappel
# author: Nick Rycar


#######################################################
# Protocol Tests                                      #
# Valid protocols are: tls1.2                         #
# Invalid protocols are : ssl2, ssl3, tls1.0, tls1.1  #
#######################################################
control 'ssl2' do
  title 'Disable SSL 2 from all exposed SSL ports.'
  impact 1.0
  describe ssl(host: 'localhost', port: 443).protocols('ssl2') do

    it { should_not be_enabled }
  end
end

control 'ssl3' do
  title 'Disable SSL 3 from all exposed SSL ports.'
  impact 1.0
  describe ssl(host: 'localhost', port: 443).protocols('ssl2') do
    it { should_not be_enabled }
  end
end

control 'tls1.0' do
  title 'Disable TLS 1.0 on exposed ports.'
  impact 0.5
  describe ssl(host: 'localhost', port: 443).protocols('tls1.0') do
    it { should_not be_enabled }
  end
end

control 'tls1.1' do
  title 'Disable TLS 1.1 on exposed ports.'
  impact 0.5
  describe ssl(host: 'localhost', port: 443).protocols('tls1.1') do
    it { should_not be_enabled }
  end
end

control 'tls1.2' do
  title 'Enable TLS 1.2 on exposed ports.'
  impact 0.5
  describe ssl(host: 'localhost', port: 443).protocols('tls1.2') do
    it { should be_enabled }
  end
end
