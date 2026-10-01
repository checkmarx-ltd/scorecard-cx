# Copyright 2020 OpenSSF Scorecard Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM checkmarx/go:1.27.1@sha256:f57e37fdc7b7ce6b5a123d8a4d5f4c1367aa3c29cb0c5879e346fdaa669db5fd AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.* ./
RUN go mod download
COPY . ./

FROM base AS build
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 make build-scorecard

FROM gcr.io/distroless/base:nonroot@sha256:29da700a46816467c7cb91058f53eac4170a4a25ac8551d316d9fd38e2c58bdf
COPY --from=build /src/scorecard /
ENTRYPOINT [ "/scorecard" ]
