// Copyright (c) 2017 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"net/http"
	"github.com/vmware/harbor/src/common"
	"github.com/vmware/harbor/src/common/dao"
	"github.com/vmware/harbor/src/common/models"
	"github.com/vmware/harbor/src/common/utils/log"
	"github.com/vmware/harbor/src/ui/config"
)

// SearchAPI handles requesst to search/:username

// Get ...
func (s *SearchAPI) SearchByUsername() {
	username := s.GetStringFromPath(":username")

	isAuthenticated := s.SecurityCtx.IsAuthenticated()
	isSysAdmin := s.SecurityCtx.IsSysAdmin()

	var projects []*models.Project
	var err error
	var user *models.User

	mode, err := config.AuthMode()
	if err != nil {
		log.Errorf("failed to get auth mode: %v", err)
		s.CustomAbort(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	if mode != common.DBAuth {
		log.Errorf("auth mode need to be : db_auth ")
		s.CustomAbort(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	if isAuthenticated && isSysAdmin {
		log.Warningf("user is authenticate and isSystemAdmin")
		queryUser := models.User{Username:username}
		err := validateName(queryUser)
		if err != nil {
			log.Warningf("Bad request in Register: %v", err)
			s.RenderError(http.StatusBadRequest, "register error:"+err.Error())
			return
		}

		log.Warningf("after validate")
		user,err = dao.GetUser(queryUser)

		if err != nil {
			log.Errorf("get user by username error: %v", err)
			s.CustomAbort(http.StatusInternalServerError, "Internal error.")
		}
		if user == nil {
			log.Warning("user with username : %S not found!",username)
			s.RenderError(http.StatusNotFound, "query user not found!")
			return
		}
		log.Warningf("get user success")
		projects, err = s.ProjectMgr.GetPublic()
		if err != nil {
			s.ParseAndHandleError("failed to get projects", err)
			return
		}
		log.Warningf("after get public projects")
		//取出projects
		mys, mErr := dao.GetProjects(&models.ProjectQueryParam{
			Member: &models.MemberQuery{
				Name: user.Username,
			},
		})

		if mErr != nil {
			s.HandleInternalServerError(fmt.Sprintf(
				"failed to get projects: %v", err))
			return
		}
		log.Warningf("after get projects of user:%s",username)


		exist := map[int64]bool{}
		for _, p := range projects {
			exist[p.ProjectID] = true
		}

		for _, p := range mys {
			if !exist[p.ProjectID] {
				projects = append(projects, p)
			}
		}

		projectIds := make([]int64, len(projects))
		for i, p := range projects {
			projectIds[i] = p.ProjectID
		}

		page, size := s.GetPaginationParams()
		query := &models.RepositoryQuery{
			ProjectIDs: projectIds,
			Name: s.GetString("q"),
			Pagination: models.Pagination{
				Page: page,
				Size: size,
			},
		}

		total, tErr := dao.GetTotalOfRepositories(query)
		if tErr != nil {
			log.Errorf("failed to get total of repositories %v", err)
			s.CustomAbort(http.StatusInternalServerError, "")
		}

		repositoryResult,rErr:= dao.GetRepositoriesWithProject(query)

		if rErr != nil {
			log.Errorf("failed to filter repositories: %v", err)
			s.CustomAbort(http.StatusInternalServerError, "")
		}
		result := &searchRepositoryPageResult{total: total, page: page, page_size: size, Repository: repositoryResult}
		s.Data["json"] = result
		s.ServeJSON()
	}else{
		s.CustomAbort(http.StatusUnauthorized, "Unauthorized or login user is not admin!")
		return
	}

}
