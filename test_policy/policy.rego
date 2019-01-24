package test_policy

import data.test_data.users
import data.test_data.restricted

default allow = false

restricted_user[user] {
    restricted[_] = user
}

allow = true {
    users[_] = input.user
    not restricted_user[input.user]
}
