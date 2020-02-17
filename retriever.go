/*
Copyright 2020 Frederic Branczyk All rights reserved.

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

package main

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type TokenRetriever interface {
	TokenFor(audience string) (string, error)
}

type tokenRetriever struct {
	logger             log.Logger
	saclient           v1.ServiceAccountInterface
	serviceAccountName string
}

func newTokenRetriever(logger log.Logger, saclient v1.ServiceAccountInterface, serviceAccountName string) TokenRetriever {
	return &tokenRetriever{
		logger:             logger,
		saclient:           saclient,
		serviceAccountName: serviceAccountName,
	}
}

func (r *tokenRetriever) TokenFor(audience string) (string, error) {
	level.Debug(r.logger).Log("msg", "performing TokenRequest", "audience", audience)
	tr, err := r.saclient.CreateToken(r.serviceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{audience},
		},
	})
	return tr.Status.Token, err
}
