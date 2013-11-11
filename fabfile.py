# fabfile.py: Used in MissionControl for placement deploys
from prezi.fabric.placement import CommonTasks, PlacementDeploy

tasks = CommonTasks(PlacementDeploy(egg_name='prezi_repoguard'), 'prezi_repoguard', {}, '/')


def prezi_repoguard(*args, **kwargs):
    tasks.deploy(*args, **kwargs)