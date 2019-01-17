package test_policy
#
#import data.test_policy.users
#import data.test_policy.restricted
#
#default allow = false
#
#restricted_user[user] {
#    restricted[_] = user
#}
#
#allow {
#    users[_] = input.user
#    not restricted_user[input.user]
#}
import data.employees
import data.subsidiaries

default allow = false

allow {
    input.actor.type = "person"
    input.actor.id
}