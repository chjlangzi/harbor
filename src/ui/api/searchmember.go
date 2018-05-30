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
	"sort"
	"strings"

	"github.com/vmware/harbor/src/common"
	"github.com/vmware/harbor/src/common/dao"
	"github.com/vmware/harbor/src/common/models"
	"github.com/vmware/harbor/src/common/utils/log"
)

// SearchAPI handles requesst to /api/membersearch

// Get ...
func (s *SearchAPI) GetByMember() {
	keyword := s.GetString("q")
	//member := s.GetString("member")
	isAuthenticated := s.SecurityCtx.IsAuthenticated()
	isSysAdmin := s.SecurityCtx.IsSysAdmin()

	var projects []*models.Project
	var err error

	if isSysAdmin {
		result, err := s.ProjectMgr.List(nil)
		if err != nil {
			s.ParseAndHandleError("failed to get projects", err)
			return
		}
		projects = result.Projects
	} else {
		projects, err = s.ProjectMgr.GetPublic()
		if err != nil {
			s.ParseAndHandleError("failed to get projects", err)
			return
		}
		if isAuthenticated {
			mys, err := s.SecurityCtx.GetMyProjects()
			if err != nil {
				s.HandleInternalServerError(fmt.Sprintf(
					"failed to get projects: %v", err))
				return
			}
			exist := map[int64]bool{}
			for _, p := range projects {
				exist[p.ProjectID] = true
			}

			for _, p := range mys {
				if !exist[p.ProjectID] {
					projects = append(projects, p)
				}
			}
		}
	}

	projectSorter := &models.ProjectSorter{Projects: projects}
	sort.Sort(projectSorter)
	projectResult := []*models.Project{}
	for _, p := range projects {
		if len(keyword) > 0 && !strings.Contains(p.Name, keyword) {
			continue
		}

		if isAuthenticated {
			roles := s.SecurityCtx.GetProjectRoles(p.ProjectID)
			if len(roles) != 0 {
				p.Role = roles[0]
			}

			if p.Role == common.RoleProjectAdmin || isSysAdmin {
				p.Togglable = true
			}
		}

		total, err := dao.GetTotalOfRepositories(&models.RepositoryQuery{
			ProjectIDs: []int64{p.ProjectID},
		})
		if err != nil {
			log.Errorf("failed to get total of repositories of project %d: %v", p.ProjectID, err)
			s.CustomAbort(http.StatusInternalServerError, "")
		}

		p.RepoCount = total

		projectResult = append(projectResult, p)
	}

	repositoryResult, err := filterRepositories(projects, keyword)
	if err != nil {
		log.Errorf("failed to filter repositories: %v", err)
		s.CustomAbort(http.StatusInternalServerError, "")
	}

	result := &searchResult{Project: projectResult, Repository: repositoryResult}
	s.Data["json"] = result
	s.ServeJSON()
}
